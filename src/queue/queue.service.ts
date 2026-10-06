/**
 * Lớp trừu tượng cho hàng đợi công việc.
 *
 * `JobQueue` cũng là mã định danh để tiêm phụ thuộc. Có thể đổi cách lưu hàng
 * đợi mà không cần sửa controller hoặc worker, chỉ cần đổi `useClass`.
 *
 * Hiện tại dùng `MongoJobQueue`, lưu trong MongoDB và hỗ trợ nhiều tiến trình
 * nhờ thao tác nhận việc nguyên tử.
 */

export interface Job<T = unknown> {
  id: string;
  name: string;
  payload: T;
  lockToken: string | null;
  /** Lần thử hiện tại, bắt đầu từ 1. */
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
  /** Thêm công việc vào hàng đợi và trả về bản ghi đã lưu. */
  abstract enqueue<T>(name: string, payload: T): Promise<Job<T>>;

  /** Đăng ký hàm xử lý theo tên công việc. */
  abstract registerHandler<T>(name: string, handler: JobHandler<T>): void;

  /**
   * Chạy hàm xử lý đã đăng ký cho công việc.
   *
   * Worker gọi `dispatch`; phương thức này tìm và chạy hàm xử lý theo
   * `job.name`.
   */
  abstract dispatch(job: Job): Promise<void>;

  /** Nhận một công việc để xử lý; trả về `null` nếu hàng đợi đang trống. */
  abstract claim(): Promise<Job | null>;

  /** Gia hạn tín hiệu hoạt động để worker tiếp tục giữ công việc. */
  abstract heartbeat(jobId: string, lockToken: string): Promise<void>;

  /** Đánh dấu công việc đã hoàn tất. */
  abstract complete(
    jobId: string,
    lockToken: string,
    resultKey?: string,
  ): Promise<void>;

  /** Đánh dấu công việc thất bại; hàng đợi xử lý việc thử lại. */
  abstract fail(jobId: string, lockToken: string, error: string): Promise<void>;

  /** Lấy thống kê hàng đợi; có thể trả về trực tiếp hoặc qua Promise. */
  abstract getStats(): QueueStats | Promise<QueueStats>;

  abstract onModuleDestroy(): Promise<void>;
}
