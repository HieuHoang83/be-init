import {
  Inject,
  Injectable,
  Logger,
  OnApplicationBootstrap,
  OnModuleDestroy,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { appConfig, QueueConfig } from '../config';
import { Job, JobQueue, NonRetryableError } from './queue.service';
import { MongoJobQueue } from './mongo-job-queue.service';

interface RunningSlot {
  stopHeartbeat: () => void;
}

/**
 * Worker xử lý công việc lấy từ MongoDB.
 *
 * Vòng lặp xử lý:
 *
 *   poll -> claim(job) -> dispatch(job) -> complete | fail
 *
 * Thao tác `claim` là nguyên tử nên worker không cần tự khóa. Khi chạy nhiều
 * tiến trình, mỗi tiến trình tự tìm việc và MongoDB phân chia công việc.
 *
 * Tín hiệu hoạt động được gia hạn song song với hàm xử lý. Nếu hàm xử lý
 * kéo dài quá `leaseMs` mà không gia hạn, công việc có thể bị thu hồi và chạy
 * đồng thời ở worker khác.
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

    // Quét ngay khi khởi động, sau đó quét theo chu kỳ đã cấu hình.
    void this.reclaim();
    this.reclaimTimer = setInterval(
      () => void this.reclaim(),
      this.cfg.reclaimIntervalMs,
    );

    // Thử nhận việc ngay, không cần chờ đến chu kỳ tiếp theo.
    void this.pump();
  }

  /* ------------------------------- Vòng lặp xử lý */

  /** Nhận việc cho đến khi hàng đợi trống hoặc đạt giới hạn chạy đồng thời. */
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

  /** Chạy một công việc và ghi nhận kết quả thành công hoặc thất bại. */
  private execute(job: Job): void {
    const queue = this.jobQueue as Partial<MongoJobQueue>;
    const started = Date.now();
    const lockToken = job.lockToken;

    if (!lockToken) {
      this.logger.error(`Job ${job.id} duoc claim nhung khong co lock token`);
      return;
    }

    // Gia hạn tín hiệu phải chạy song song với hàm xử lý. Nếu không, công việc
    // kéo dài quá leaseMs có thể bị thu hồi và chạy trùng ở worker khác.
    const timer = setInterval(() => {
      void queue.heartbeat?.(job.id, lockToken).catch(() => undefined);
    }, this.cfg.heartbeatIntervalMs);

    this.running.set(job.id, { stopHeartbeat: () => clearInterval(timer) });

    void (async (): Promise<void> => {
      try {
        await this.jobQueue.dispatch(job);

        if (typeof queue.complete === 'function') {
          await queue.complete(job.id, lockToken, job.result);
        }
        this.logger.log(
          `Job ${job.id} (${job.name}) xong trong ${Date.now() - started}ms`,
        );
      } catch (error) {
        const message = (error as Error).message ?? String(error);
        try {
          // Lỗi dữ liệu (400/422…) thử lại cũng vậy, nên đánh dấu thất bại ngay.
          const retry = !(error instanceof NonRetryableError);
          await queue.fail?.(job.id, lockToken, message, { retry });
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
        // Hàng đợi vừa có chỗ trống; thử nhận thêm việc.
        void this.pump();
      }
    })();
  }

  /** Đưa công việc hết hạn giữ trở lại trạng thái chờ. */
  private async reclaim(): Promise<void> {
    const queue = this.jobQueue as Partial<MongoJobQueue>;
    if (typeof queue.reclaimExpired !== 'function') return;
    try {
      await queue.reclaimExpired();
    } catch (error) {
      this.logger.error(`Reclaim job loi: ${(error as Error).message}`);
    }
  }

  /* ------------------------------- Dọn dẹp */

  async onModuleDestroy(): Promise<void> {
    this.stopping = true;
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.reclaimTimer) clearInterval(this.reclaimTimer);

    // Dừng gia hạn nhưng không hủy công việc. Khi hết hạn giữ, worker khác
    // có thể nhận lại; hủy ngay sẽ làm mất công việc đang xử lý.
    for (const slot of this.running.values()) slot.stopHeartbeat();
    this.running.clear();

    this.logger.log(
      'Job worker da dung (job dang chay se het lease roi chay lai)',
    );
  }
}
