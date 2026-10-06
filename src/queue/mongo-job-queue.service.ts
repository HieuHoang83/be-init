import { Inject, Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { randomBytes, randomUUID } from 'node:crypto';
import { appConfig, QueueConfig } from '../config';
import { JobQueue, Job, QueueStats } from './queue.service';
import { Job as JobEntity, JobDocument, JobStatus } from './job.entity';

/* ------------------------------------------------------------------ ULID */

/** Crockford base32, khong chua I/L/O/U de goi doc khong nham */
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
let lastMs = 0;
let lastRandom: number[] = [];

function encodeTime(now: number, len = 10): string {
  let out = '';
  let n = now;
  for (let i = len - 1; i >= 0; i--) {
    out = CROCKFORD[n % 32] + out;
    n = Math.floor(n / 32);
  }
  return out;
}

function encodeRandom(len: number): string {
  const out: string[] = [];
  for (let i = 0; i < len; i++) out.push(CROCKFORD[lastRandom[i] % 32]);
  return out.join('');
}

/**
 * ULID 26 ky tu: 10 ky tu timestamp + 16 ky tu ngau nhien.
 * Sap xep theo thu tu thoi gian nen index `createdAt` van du dung.
 * Trong cung 1 ms thi tang `lastRandom` de id khong trung.
 */
export function ulid(): string {
  const now = Date.now();

  if (now === lastMs) {
    // cung millisecond -> tang so ngau nhien 1 don
    for (let i = lastRandom.length - 1; i >= 0; i--) {
      if (lastRandom[i] < 31) {
        lastRandom[i] += 1;
        break;
      }
      lastRandom[i] = 0;
    }
  } else {
    lastMs = now;
    const bytes = randomBytes(16);
    lastRandom = Array.from(bytes, (b) => b % 32);
  }

  return encodeTime(now) + encodeRandom(16);
}

/* --------------------------------------------------------------- helpers */

export type DbJob = JobEntity & { _id: unknown };

/**
 * Hang doi cong viec luu trong MongoDB.
 *
 * Thay the `InProcessJobQueue` ma khong can doi controller/worker: module chi
 * doi `useClass`, abstraction `JobQueue` giu nguyen.
 *
 * Ba co che chinh:
 *
 * 1. CLAIM ATOMIC - `findOneAndUpdate` loc `{status:'pending'}` roi sap xep
 *    `createdAt` tang dan. Mongo dam bao chi mot worker nhan duoc cung mot
 *    job, nen khong can khoa phan tach khi chay nhieu instance.
 *
 * 2. LEASE + HEARTBEAT - worker giu job bang `lockedBy`/`heartbeatAt` va
 *    nap lai moi `heartbeatIntervalMs`. Job co `heartbeatAt` cu hon
 *    `now - leaseMs` bi tra ve `pending` (worker do da chet).
 *
 * 3. RETRY BACKOFF - that bai thi tang `attempts`; con du so lan thi quay lai
 *    `pending` kem `availableAt = now + backoff`. Het `maxAttempts` thi
 *    chuyen `failed` va giu nguyen error de doc lai.
 */
@Injectable()
export class MongoJobQueue extends JobQueue implements OnModuleDestroy {
  private readonly logger = new Logger(MongoJobQueue.name);

  private readonly cfg: QueueConfig;
  private readonly workerId: string;

  /** handler theo `type`, dung chung voi InProcessJobQueue */
  private readonly handlers = new Map<string, (job: Job) => Promise<void>>();

  /** Dem cho JobStats, ton tai trong RAM nen reset khi restart - OK */
  private processed = 0;
  private failed = 0;
  private retried = 0;

  constructor(
    @InjectModel(JobEntity.name) private readonly jobModel: Model<JobDocument>,
    @Inject(appConfig.KEY) config: ConfigType<typeof appConfig>,
  ) {
    super();
    this.cfg = config.queue;
    this.workerId = `${process.env.HOSTNAME ?? 'worker'}-${process.pid}`;
  }

  /* ------------------------------------------------------------- enqueue */

  async enqueue<T>(name: string, payload: T): Promise<Job<T>> {
    if (!this.handlers.has(name)) {
      throw new Error(`Khong co handler cho job "${name}"`);
    }

    const now = new Date();
    const doc = await this.jobModel.create({
      id: ulid(),
      type: name,
      status: 'pending',
      payload: payload as Record<string, unknown>,
      attempts: 0,
      maxAttempts: this.cfg.maxAttempts,
      totalRows: null,
      processedRows: 0,
      availableAt: now,
    });

    return {
      id: doc.id,
      name,
      payload,
      // attempt hien tai = da thu + 1
      attempt: 1,
      maxAttempts: doc.maxAttempts,
      enqueuedAt: now,
      lockToken: null,
    };
  }

  registerHandler<T>(
    name: string,
    handler: (job: Job<T>) => Promise<void>,
  ): void {
    this.handlers.set(name, handler as (job: Job) => Promise<void>);
  }

  hasHandler(type: string): boolean {
    return this.handlers.has(type);
  }

  async dispatch(job: Job): Promise<void> {
    const handler = this.handlers.get(job.name);
    if (!handler) throw new Error(`Khong co handler cho job "${job.name}"`);
    await handler(job);
  }

  /* --------------------------------------------------------------- claim */

  /**
   * Nhat job cho worker nay chay.
   *
   * `findOneAndUpdate` la atomic: Mongo gan luon mot ban ghi cho mot
   * `findAndModify`, nen worker A va worker B goi cung luc chi mot ben
   * nhan duoc job. Tra `null` khi hang rong.
   */
  async claim(): Promise<Job | null> {
    const now = new Date();
    const lockToken = randomUUID();

    const doc = await this.jobModel
      .findOneAndUpdate(
        {
          status: 'pending',
          availableAt: { $lte: now },
        },
        {
          $set: {
            status: 'running',
            lockedBy: this.workerId,
            lockedAt: now,
            heartbeatAt: now,
            startedAt: now,
            lockToken,
          },
          // Lan chay tiep theo moi tinh la 1 lan thu
          $inc: { attempts: 1 },
        },
        {
          // Job cu chay truoc
          sort: { createdAt: 1 },
          new: true,
        },
      )
      .exec();

    if (!doc) return null;

    return {
      id: doc.id,
      name: doc.type,
      payload: doc.payload,
      attempt: doc.attempts,
      maxAttempts: doc.maxAttempts,
      enqueuedAt: doc.createdAt ?? now,
      lockToken: doc.lockToken ?? lockToken,
    };
  }

  /** Nap lai `heartbeatAt` de worker khong bi giu job khi xu ly dai. */
  async heartbeat(jobId: string, lockToken: string): Promise<void> {
    await this.jobModel
      .updateOne(
        { id: jobId, status: 'running', lockedBy: this.workerId, lockToken },
        { $set: { heartbeatAt: new Date() } },
      )
      .exec();
  }

  /** Cap nhat checkpoint tien do. */
  async reportProgress(
    jobId: string,
    lockToken: string,
    processedRows: number,
    totalRows?: number | null,
  ): Promise<void> {
    const set: Record<string, unknown> = { processedRows };
    if (totalRows !== undefined) set['totalRows'] = totalRows;
    await this.jobModel
      .updateOne(
        { id: jobId, status: 'running', lockedBy: this.workerId, lockToken },
        { $set: set },
      )
      .exec();
  }

  /* ---------------------------------------------------------- complete/fail */

  async complete(
    jobId: string,
    lockToken: string,
    resultKey?: string,
  ): Promise<void> {
    const result = await this.jobModel
      .updateOne(
        { id: jobId, status: 'running', lockedBy: this.workerId, lockToken },
        {
          $set: {
            status: 'completed',
            finishedAt: new Date(),
            resultKey: resultKey ?? null,
          },
          $unset: {
            lockedBy: '',
            lockedAt: '',
            heartbeatAt: '',
            lockToken: '',
            error: '',
          },
        },
      )
      .exec();
    if (result.modifiedCount > 0) this.processed += 1;
  }

  /**
   * Job that bai. Con du so lan -> `pending` + backoff; het -> `failed`.
   * Khong xoa `lockedBy` khi retry de tiet kiem mot lan ghi.
   */
  async fail(jobId: string, lockToken: string, error: string): Promise<void> {
    const owner = {
      id: jobId,
      status: 'running',
      lockedBy: this.workerId,
      lockToken,
    };
    const doc = await this.jobModel.findOne(owner).exec();
    if (!doc) return;

    const willRetry = doc.attempts < doc.maxAttempts;
    const delay = this.backoffMs(doc.attempts);

    const result = await this.jobModel
      .updateOne(owner, {
        $set: {
          status: willRetry ? 'pending' : 'failed',
          availableAt: new Date(Date.now() + delay),
          finishedAt: willRetry ? null : new Date(),
          error: error.slice(0, 2000),
        },
        $unset: {
          lockedBy: '',
          lockedAt: '',
          heartbeatAt: '',
          lockToken: '',
        },
      })
      .exec();
    if (result.modifiedCount === 0) return;

    if (willRetry) {
      this.retried += 1;
      this.logger.warn(
        `Job ${jobId} (${doc.type}) that bai: ${error}. ` +
          `Thu lai lan ${doc.attempts + 1}/${doc.maxAttempts} sau ${delay}ms`,
      );
    } else {
      this.failed += 1;
      this.logger.error(
        `Job ${jobId} (${doc.type}) that bai het ${doc.maxAttempts} lan: ${error}`,
      );
    }
  }

  /** Exponential backoff: base * 2^(attempts-1), cap o backoffMaxMs. */
  private backoffMs(attempts: number): number {
    return Math.min(
      this.cfg.backoffBaseMs * 2 ** Math.max(attempts - 1, 0),
      this.cfg.backoffMaxMs,
    );
  }

  /* -------------------------------------------------------------- orphan */

  /**
   * Tra job cua worker da chet ve `pending`.
   *
   * Worker dung nhip tim (`heartbeatAt`) nen qua `leaseMs` khong nhip la
   * da chet. Job phai dung lai `attempts` - neu khong, job se that bai lien
   * tuc va het luot retry chi vi worker chet, khong vi loi nghiep vu.
   */
  async reclaimExpired(count = 100): Promise<number> {
    const deadline = new Date(Date.now() - this.cfg.leaseMs);
    const expiredJobs = await this.jobModel
      .find({ status: 'running', heartbeatAt: { $lt: deadline } })
      .select('id lockedBy lockToken heartbeatAt')
      .limit(count)
      .lean()
      .exec();

    let reclaimed = 0;
    for (const job of expiredJobs) {
      const result = await this.jobModel
        .updateOne(
          {
            id: job.id,
            status: 'running',
            lockedBy: job.lockedBy,
            lockToken: job.lockToken,
            $and: [
              { heartbeatAt: job.heartbeatAt },
              { heartbeatAt: { $lt: deadline } },
            ],
          },
          {
            $set: {
              status: 'pending',
              availableAt: new Date(),
              error:
                'Lease het han (worker khong con nhip tim), tra ve pending',
            },
            $inc: { attempts: -1 },
            $unset: {
              lockedBy: '',
              lockedAt: '',
              heartbeatAt: '',
              lockToken: '',
            },
          },
        )
        .exec();
      reclaimed += result.modifiedCount;
    }

    if (reclaimed > 0) {
      this.logger.warn(`Tra ${reclaimed} job het lease ve pending`);
    }
    return reclaimed;
  }

  /* --------------------------------------------------------------- stats */

  /** Doc truc tiep tu DB nen bao cao dung ke ca sau khi restart. */
  async getStats(): Promise<QueueStats> {
    const grouped = await this.jobModel.aggregate<{
      _id: JobStatus;
      n: number;
    }>([{ $group: { _id: '$status', n: { $sum: 1 } } }]);

    const by = (status: JobStatus): number =>
      grouped.find((g) => g._id === status)?.n ?? 0;

    return {
      driver: 'mongodb',
      pending: by('pending'),
      running: by('running'),
      processed: by('completed'),
      failed: by('failed'),
      retried: this.retried,
    };
  }

  /* -------------------------------------------------------------- shutdown */

  /**
   * Khong dung gi khi shutdown.
   *
   * Job dang `running` co `lockedBy` cua worker nay, het lease se
   * `reclaimExpired` dua ve `pending` - worker moi chay lai. Xoa o day se
   * lam mat cong viec dang xu ly giua duong.
   */
  async onModuleDestroy(): Promise<void> {
    this.logger.log(
      'Mongo job queue dung (job dang chay se het lease roi chay lai)',
    );
  }

  /* -------------------------------------------------------------- helpers */

  /** Xoa job cu xong, giữ `keepFinished` ban ghi moi nhat de tránh phinh toan. */
  async purgeCompleted(olderThanDays = 7): Promise<number> {
    const deadline = new Date(Date.now() - olderThanDays * 86_400_000);
    const res = await this.jobModel.deleteMany({
      status: { $in: ['completed', 'failed'] },
      finishedAt: { $lt: deadline },
    });
    return res.deletedCount ?? 0;
  }
}
