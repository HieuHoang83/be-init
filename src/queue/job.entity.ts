import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

/**
 * Trạng thái công việc.
 *
 * `retry` không phải trạng thái riêng: công việc còn lượt thử sẽ trở về
 * `pending` với `availableAt` được đặt theo thời gian chờ. Vì vậy, truy vấn
 * nhận việc chỉ cần tìm trạng thái `pending` đã đến hạn.
 */
export const JOB_STATUSES = [
  'pending',
  'running',
  'completed',
  'failed',
] as const;
export type JobStatus = typeof JOB_STATUSES[number];

/** Loại công việc, dùng chung cho trường `type` và hàm xử lý. */
export const JOB_TYPES = {
  ORDER_CREATED: 'order.created',
  ORDER_CONFIRM: 'order.confirm',
  ORDER_SYNC_CUSTOMER: 'order.sync_customer',
} as const;
export type JobType = typeof JOB_TYPES[keyof typeof JOB_TYPES];

/**
 * Hàng đợi công việc được lưu trong MongoDB.
 *
 * Cấu trúc tương đương trong SQL:
 *   CREATE TABLE jobs (
 *     id uuid PRIMARY KEY,  type, status, payload, processed_rows,
 *     total_rows, attempts, max_attempts, locked_by, heartbeat_at,
 *     error, result_key, created_at, started_at, finished_at
 *   );
 *   CREATE INDEX idx_jobs_claim ON jobs (status, created_at);
 *
 * Hai trường bổ sung giúp hàng đợi hoạt động an toàn:
 *   - `availableAt`: công việc chưa đến hạn thử lại sẽ không được nhận.
 *   - `lockedAt`: thời điểm worker nhận việc, dùng để tính thời hạn giữ việc.
 */
@Schema({ collection: 'jobs', timestamps: true })
export class Job {
  /** ULID được tạo trong ứng dụng và sắp xếp theo thời gian. */
  @Prop({ required: true, unique: true, index: true })
  id!: string;

  @Prop({ required: true })
  type!: string;

  @Prop({ required: true, enum: JOB_STATUSES, default: 'pending' })
  status!: JobStatus;

  /** Dữ liệu công việc; MongoDB lưu trực tiếp dưới dạng object. */
  @Prop({ required: true, type: Object, default: {} })
  payload!: Record<string, unknown>;

  /** Số dòng đã xử lý đến thời điểm hiện tại. */
  @Prop({ default: 0 })
  processedRows!: number;

  @Prop({ default: null })
  totalRows?: number | null;

  /** Số lần đã thử trước lần đang chạy. */
  @Prop({ default: 0 })
  attempts!: number;

  @Prop({ default: 3 })
  maxAttempts!: number;

  @Prop() lockedBy?: string;
  @Prop() lockedAt?: Date;
  @Prop() lockToken?: string;

  /** Thời điểm gần nhất worker báo vẫn đang hoạt động. */
  @Prop() heartbeatAt?: Date;

  @Prop() error?: string;

  /** Khóa tham chiếu đến kết quả trên bộ lưu trữ đối tượng. */
  @Prop() resultKey?: string;

  /** Chỉ nhận công việc khi đã đến thời điểm này. */
  @Prop({ default: () => new Date(), index: true })
  availableAt!: Date;

  @Prop() startedAt?: Date;
  @Prop() finishedAt?: Date;

  /** Mongoose tự tạo các mốc thời gian; ưu tiên nhận việc cũ trước. */
  createdAt?: Date;
  updatedAt?: Date;
}

export type JobDocument = HydratedDocument<Job>;
export const JobSchema = SchemaFactory.createForClass(Job);

/**
 * Chỉ mục để tìm công việc đang chờ theo trạng thái và thời gian tạo,
 * giúp nhận công việc cũ nhất trước.
 */
JobSchema.index({ status: 1, createdAt: 1 });

/** Tìm công việc đang chờ đã đến hạn chạy lại. */
JobSchema.index({ status: 1, availableAt: 1 });

/** Tìm công việc worker đang giữ để gia hạn hoặc thu hồi khi bị bỏ dở. */
JobSchema.index({ lockedBy: 1, heartbeatAt: 1 });

/** Dùng cho bảng điều khiển và lọc theo loại công việc. */
JobSchema.index({ type: 1, createdAt: -1 });
