/**
 * Abstraction cua hang doi cong viec.
 *
 * `JobQueue` la abstract class nen chinh no la DI token: doi backend hang doi
 * khong can doi controller hay worker, chi doi `useClass` trong `QueueModule`.
 *
 * Trien khai hien tai: `MongoJobQueue` - luu job trong MongoDB, dung duoc khi
 * chay nhieu instance vi Mongo chua atomic claim.
 */

export interface Job<T = unknown> {
  id: string;
  name: string;
  payload: T;
  lockToken: string | null;
  /** Lan thu hien tai, tinh tu 1 */
  attempt: number;
  maxAttempts: number;
  enqueuedAt: Date;
}

export type JobHandler<T = unknown> = (job: Job<T>) => Promise<void>;

export const JOB_NAMES = {
  ORDER_CREATED: 'order.created',
  ORDER_CONFIRM: 'order.confirm',
  ORDER_SYNC_CUSTOMER: 'order.sync_customer',
} as const;

export type JobName = typeof JOB_NAMES[keyof typeof JOB_NAMES];

export interface QueueStats {
  driver: string;
  pending: number;
  running: number;
  processed: number;
  failed: number;
  retried: number;
}

export abstract class JobQueue {
  /** Dua job vao hang, tra ve job da ghi vao DB. */
  abstract enqueue<T>(name: string, payload: T): Promise<Job<T>>;

  /** Worker dinh ky handler theo `name` (= `type` cua job). */
  abstract registerHandler<T>(name: string, handler: JobHandler<T>): void;

  /**
   * Chay handler da dang ky cho job.
   *
   * Worker khong duoc tu giu registry - no chi goi `dispatch` de mot noi
   * duy nhat tim handler theo `job.name` va chay.
   */
  abstract dispatch(job: Job): Promise<void>;

  /** Nhat job cho worker chay. Tra `null` khi hang rong. */
  abstract claim(): Promise<Job | null>;

  /** Nap lai nhip tim de worker giu duoc job. */
  abstract heartbeat(jobId: string, lockToken: string): Promise<void>;

  /** Danh dau job xong. */
  abstract complete(
    jobId: string,
    lockToken: string,
    resultKey?: string,
  ): Promise<void>;

  /** Danh dau job that bai; queue lo phan retry/backoff. */
  abstract fail(jobId: string, lockToken: string, error: string): Promise<void>;

  /** Mongo driver tra Promise, driver khac co the tra gia tri ngay. */
  abstract getStats(): QueueStats | Promise<QueueStats>;

  abstract onModuleDestroy(): Promise<void>;
}
