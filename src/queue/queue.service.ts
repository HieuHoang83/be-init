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
  /**
   * Kết quả ngắn mà handler ghi sau khi xử lý xong. Worker truyền giá trị này
   * cho `complete` để lưu vào `resultKey`, nhờ đó FE hiển thị được thông báo.
   */
  result?: string;
}

export type JobHandler<T = unknown> = (job: Job<T>) => Promise<void>;

/**
 * Lỗi không thử lại được (sai dữ liệu, 422, 400…). Worker sẽ đánh dấu job
 * thất bại ngay thay vì mất thêm vài giây chờ rồi thử lại y hệt.
 */
export class NonRetryableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NonRetryableError';
  }
}

export const JOB_NAMES = {
  ORDER_CREATED: 'order.created',
  /** Tạo đơn hàng trên Haravan theo yêu cầu của người dùng. */
  ORDER_CREATE: 'order.create',
  ORDER_CONFIRM: 'order.confirm',
  ORDER_CANCEL: 'order.cancel',
  ORDER_CLOSE: 'order.close',
  ORDER_OPEN: 'order.open',
  ORDER_UPDATE: 'order.update',
  ORDER_REFUND: 'order.refund',
  ORDER_TRANSACTION: 'order.transaction',
  ORDER_SYNC_CUSTOMER: 'order.sync_customer',
} as const;

export type JobName = typeof JOB_NAMES[keyof typeof JOB_NAMES];

/** Tuỳ chọn khi thêm công việc vào hàng đợi. */
export interface EnqueueOptions {
  /**
   * Giới hạn số lần thử cho riêng công việc này. Công việc tạo đơn để mặc định
   * `1`: nếu Haravan đã tạo xong mà phản hồi thất lạc, thử lại sẽ sinh đơn nhép.
   */
  maxAttempts?: number;
}

/** Hình dạng công việc trả về cho API (FE poll theo id). */
export interface JobView {
  id: string;
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  attempts: number;
  maxAttempts: number;
  error?: string | null;
  result?: string | null;
  payload?: Record<string, unknown> | null;
  createdAt?: Date;
  finishedAt?: Date | null;
}

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
  abstract enqueue<T>(
    name: string,
    payload: T,
    options?: EnqueueOptions,
  ): Promise<Job<T>>;

  /** Đọc trạng thái hiện tại của một công việc để FE poll. */
  abstract findById(jobId: string): Promise<JobView | null>;

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
  abstract fail(
    jobId: string,
    lockToken: string,
    error: string,
    options?: { retry?: boolean },
  ): Promise<void>;

  /** Lấy thống kê hàng đợi; có thể trả về trực tiếp hoặc qua Promise. */
  abstract getStats(): QueueStats | Promise<QueueStats>;

  abstract onModuleDestroy(): Promise<void>;
}
