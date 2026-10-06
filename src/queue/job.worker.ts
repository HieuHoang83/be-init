import {
  Inject,
  Injectable,
  Logger,
  OnApplicationBootstrap,
  OnModuleDestroy,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { appConfig, QueueConfig } from '../config';
import { Job, JobQueue } from './queue.service';
import { MongoJobQueue } from './mongo-job-queue.service';

interface RunningSlot {
  stopHeartbeat: () => void;
}

/**
 * Worker chay job tu MongoDB.
 *
 * Vong lap don gian, dung y intentionally:
 *
 *   poll -> claim(job) -> dispatch(job) -> complete | fail
 *
 * `claim` la atomic nen worker khong can khoa. Muon chay nhieu instance
 * (PM2 cluster, may khac) thi moi instance tu poll, Mongo chia job.
 *
 * Heartbeat chay song song voi handler: handler don (goi Omni API) co the
 * treo > leaseMs, neu khong nap lai `heartbeatAt` thi job bi chinh no
 * reclaim va chay lai 2 lan.
 */
@Injectable()
export class JobWorker implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(JobWorker.name);

  private readonly cfg: QueueConfig;
  private readonly running = new Map<string, RunningSlot>();

  private stopping = false;
  private pumping = false;
  private pollTimer: NodeJS.Timeout | null = null;
  private reclaimTimer: NodeJS.Timeout | null = null;

  constructor(
    private readonly jobQueue: JobQueue,
    @Inject(appConfig.KEY) config: ConfigType<typeof appConfig>,
  ) {
    this.cfg = config.queue;
  }

  onApplicationBootstrap(): void {
    if (!this.cfg.enabled) {
      this.logger.warn('Job worker bi TAT (JOB_QUEUE_ENABLED=false)');
      return;
    }

    this.logger.log(
      `Job worker bat dau (poll ${this.cfg.pollIntervalMs}ms, ` +
        `lease ${this.cfg.leaseMs}ms, concurrency ${this.cfg.concurrency})`,
    );

    this.pollTimer = setInterval(
      () => void this.pump(),
      this.cfg.pollIntervalMs,
    );

    // Quet ngay luc khoi dong, sau do quet theo chu ky cau hinh.
    void this.reclaim();
    this.reclaimTimer = setInterval(
      () => void this.reclaim(),
      this.cfg.reclaimIntervalMs,
    );

    // Claim ngay mot lan thay vi doi 1 giay
    void this.pump();
  }

  /* ------------------------------------------------------------------ loop */

  /** Lay job cho den khi het hang hoac cham concurrency. */
  private async pump(): Promise<void> {
    if (this.pumping || this.stopping) return;
    this.pumping = true;

    try {
      while (!this.stopping && this.running.size < this.cfg.concurrency) {
        const job = await this.jobQueue.claim();
        if (!job) break;
        this.execute(job);
      }
    } catch (error) {
      this.logger.error(`Worker poll loi: ${(error as Error).message}`);
    } finally {
      this.pumping = false;
    }
  }

  /** Chay 1 job: bat heartbeat, chay handler, phan biet thanh cong/that bai. */
  private execute(job: Job): void {
    const queue = this.jobQueue as Partial<MongoJobQueue>;
    const started = Date.now();
    const lockToken = job.lockToken;

    if (!lockToken) {
      this.logger.error(`Job ${job.id} duoc claim nhung khong co lock token`);
      return;
    }

    // Heartbeat phai chay SONG SONG voi handler. Handler don (goi Omni API)
    // co the treo > leaseMs; neu khong nap lai heartbeat, job bi chinh no
    // reclaim va chay trung.
    const timer = setInterval(() => {
      void queue.heartbeat?.(job.id, lockToken).catch(() => undefined);
    }, this.cfg.heartbeatIntervalMs);

    this.running.set(job.id, { stopHeartbeat: () => clearInterval(timer) });

    void (async (): Promise<void> => {
      try {
        await this.jobQueue.dispatch(job);

        if (typeof queue.complete === 'function') {
          await queue.complete(job.id, lockToken);
        }
        this.logger.log(
          `Job ${job.id} (${job.name}) xong trong ${Date.now() - started}ms`,
        );
      } catch (error) {
        const message = (error as Error).message ?? String(error);
        try {
          await queue.fail?.(job.id, lockToken, message);
        } catch (failErr) {
          this.logger.error(
            `Khong ghi duoc loi cho job ${job.id}: ${
              (failErr as Error).message
            }`,
          );
        }
      } finally {
        this.running.get(job.id)?.stopHeartbeat();
        this.running.delete(job.id);
        // Hang vua trong -> claim them
        void this.pump();
      }
    })();
  }

  /** Tra job cua worker da chet ve `pending`. */
  private async reclaim(): Promise<void> {
    const queue = this.jobQueue as Partial<MongoJobQueue>;
    if (typeof queue.reclaimExpired !== 'function') return;
    try {
      await queue.reclaimExpired();
    } catch (error) {
      this.logger.error(`Reclaim job loi: ${(error as Error).message}`);
    }
  }

  /* ---------------------------------------------------------------- cleanup */

  async onModuleDestroy(): Promise<void> {
    this.stopping = true;
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.reclaimTimer) clearInterval(this.reclaimTimer);

    // Dung heartbeat dang chay, KHONG huy job - no se het lease va worker
    // khac nham lai. Huy job o day se mat cong viec dang chay.
    for (const slot of this.running.values()) slot.stopHeartbeat();
    this.running.clear();

    this.logger.log(
      'Job worker da dung (job dang chay se het lease roi chay lai)',
    );
  }
}
