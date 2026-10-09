import { Inject, Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { randomBytes, randomUUID } from 'node:crypto';
import { appConfig, QueueConfig } from '../config';
import {
  EnqueueOptions,
  JobQueue,
  Job,
  JobView,
  QueueStats,
} from './queue.service';
import { Job as JobEntity, JobDocument, JobStatus } from './job.entity';

/* ---------------------------------- Tạo ULID */

/** Mã hóa Crockford Base32, bỏ I, L, O và U để tránh nhầm lẫn khi đọc. */
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
 * ULID gồm 26 ký tự: 10 ký tự thời gian và 16 ký tự ngẫu nhiên.
 * Mã sắp xếp theo thời gian; trong cùng một mili giây, phần ngẫu nhiên tăng
 * để tránh tạo mã trùng.
 */
export function ulid(): string {
  const now = Date.now();

  if (now === lastMs) {
    // Nếu vẫn trong cùng mili giây, tăng phần ngẫu nhiên lên một đơn vị.
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

/* --------------------------------- Tiện ích */

export type DbJob = JobEntity & { _id: unknown };

/**
 * Hàng đợi công việc được lưu trong MongoDB.
 *
 * Có thể thay `InProcessJobQueue` mà không cần sửa controller hoặc worker;
 * chỉ cần đổi `useClass`, còn `JobQueue` vẫn giữ nguyên.
 *
 * Ba cơ chế chính:
 *
 * 1. Nhận việc nguyên tử: `findOneAndUpdate` lọc trạng thái chờ và sắp xếp
 *    theo `createdAt`. MongoDB bảo đảm chỉ một worker nhận được mỗi công việc.
 *
 * 2. Thời hạn giữ và tín hiệu hoạt động: worker gia hạn `heartbeatAt` theo
 *    chu kỳ. Công việc quá hạn được trả về trạng thái chờ.
 *
 * 3. Thử lại có giãn cách: khi thất bại, tăng `attempts`. Nếu còn lượt thử,
 *    đưa công việc về trạng thái chờ và đặt `availableAt`; nếu hết lượt,
 *    chuyển sang thất bại và giữ lại lỗi.
 */
@Injectable()
export class MongoJobQueue extends JobQueue implements OnModuleDestroy {
  private readonly logger = new Logger(MongoJobQueue.name);

  private readonly cfg: QueueConfig;
  private readonly workerId: string;

  /** Ánh xạ loại công việc với hàm xử lý. */
  private readonly handlers = new Map<string, (job: Job) => Promise<void>>();

  /** Bộ đếm thống kê trong bộ nhớ; được đặt lại khi ứng dụng khởi động lại. */
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

  /* --------------------------------- Thêm công việc */

  async enqueue<T>(
    name: string,
    payload: T,
    options: EnqueueOptions = {},
  ): Promise<Job<T>> {
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
      maxAttempts: options.maxAttempts ?? this.cfg.maxAttempts,
      totalRows: null,
      processedRows: 0,
      availableAt: now,
    });

    return {
      id: doc.id,
      name,
      payload,
      // Lần thử hiện tại bằng số lần đã thử cộng một.
      attempt: 1,
      maxAttempts: doc.maxAttempts,
      enqueuedAt: now,
      lockToken: null,
    };
  }

  /** Đọc một công việc theo id; FE dùng để theo dõi kết quả thao tác. */
  async findById(jobId: string): Promise<JobView | null> {
    if (!jobId?.trim()) return null;
    const doc = await this.jobModel.findOne({ id: jobId }).lean().exec();
    if (!doc) return null;
    return {
      id: doc.id,
      name: doc.type,
      status: doc.status,
      attempts: doc.attempts,
      maxAttempts: doc.maxAttempts,
      error: doc.error ?? null,
      result: doc.resultKey ?? null,
      payload: (doc.payload ?? null) as Record<string, unknown> | null,
      createdAt: doc.createdAt ?? undefined,
      finishedAt: doc.finishedAt ?? null,
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

  /* -------------------------------- Nhận công việc */

  /**
   * Nhận một công việc để worker này xử lý.
   *
   * `findOneAndUpdate` là thao tác nguyên tử: nếu nhiều worker gọi cùng lúc,
   * chỉ một worker nhận được công việc. Trả về `null` nếu hàng đợi trống.
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
          // Chỉ tính thêm một lượt khi bắt đầu chạy công việc.
          $inc: { attempts: 1 },
        },
        {
          // Ưu tiên công việc được tạo trước.
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

  /** Gia hạn `heartbeatAt` để công việc chạy lâu không bị thu hồi. */
  async heartbeat(jobId: string, lockToken: string): Promise<void> {
    await this.jobModel
      .updateOne(
        { id: jobId, status: 'running', lockedBy: this.workerId, lockToken },
        { $set: { heartbeatAt: new Date() } },
      )
      .exec();
  }

  /** Cập nhật số dòng đã xử lý. */
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

  /* --------------------------- Hoàn tất hoặc đánh dấu thất bại */

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
   * Nếu còn lượt thử, đưa công việc về `pending` và chờ theo backoff;
   * nếu hết lượt, chuyển sang `failed`.
   */
  async fail(
    jobId: string,
    lockToken: string,
    error: string,
    options: { retry?: boolean } = {},
  ): Promise<void> {
    const owner = {
      id: jobId,
      status: 'running',
      lockedBy: this.workerId,
      lockToken,
    };
    const doc = await this.jobModel.findOne(owner).exec();
    if (!doc) return;

    const willRetry = (options.retry ?? true) && doc.attempts < doc.maxAttempts;
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

  /** Tính thời gian chờ tăng dần, không vượt quá `backoffMaxMs`. */
  private backoffMs(attempts: number): number {
    return Math.min(
      this.cfg.backoffBaseMs * 2 ** Math.max(attempts - 1, 0),
      this.cfg.backoffMaxMs,
    );
  }

  /* ------------------------------ Thu hồi công việc bỏ dở */

  /**
   * Đưa công việc của worker đã dừng trở lại trạng thái chờ.
   *
   * Worker gia hạn `heartbeatAt`; nếu quá `leaseMs` không có tín hiệu mới,
   * xem như worker đã dừng. Hoàn lại lượt thử để công việc không bị tính là
   * thất bại chỉ vì worker dừng đột ngột.
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

  /* --------------------------------- Thống kê */

  /** Đọc trực tiếp từ cơ sở dữ liệu nên số liệu vẫn chính xác sau khi khởi động lại. */
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

  /* --------------------------------- Dừng dịch vụ */

  /**
   * Không thay đổi trạng thái công việc khi dừng dịch vụ.
   *
   * Công việc đang chạy sẽ được `reclaimExpired` trả về trạng thái chờ khi
   * hết thời hạn giữ để worker khác xử lý. Xóa ngay sẽ làm mất công việc.
   */
  async onModuleDestroy(): Promise<void> {
    this.logger.log(
      'Hàng đợi MongoDB đã dừng (công việc đang chạy sẽ được nhận lại khi hết hạn)',
    );
  }

  /* --------------------------------- Tiện ích */

  /** Xóa công việc đã kết thúc quá lâu để tránh làm cơ sở dữ liệu phình to. */
  async purgeCompleted(olderThanDays = 7): Promise<number> {
    const deadline = new Date(Date.now() - olderThanDays * 86_400_000);
    const res = await this.jobModel.deleteMany({
      status: { $in: ['completed', 'failed'] },
      finishedAt: { $lt: deadline },
    });
    return res.deletedCount ?? 0;
  }
}
