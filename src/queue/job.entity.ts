import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

/**
 * Trang thai job.
 *
 * `retry` KHONG phai trang thai rieng: job that bai co `attempts < maxAttempts`
 * se quay lai `pending` kèm `availableAt` = now + backoff. Vay query claim
 * chi can `{ status: 'pending', availableAt <= now }` - don gian hon.
 */
export const JOB_STATUSES = [
  'pending',
  'running',
  'completed',
  'failed',
] as const;
export type JobStatus = typeof JOB_STATUSES[number];

/** Loai job, dung chung cho ca `type` va handler. */
export const JOB_TYPES = {
  ORDER_CREATED: 'order.created',
  ORDER_CONFIRM: 'order.confirm',
  ORDER_SYNC_CUSTOMER: 'order.sync_customer',
} as const;
export type JobType = typeof JOB_TYPES[keyof typeof JOB_TYPES];

/**
 * Hang doi cong viec luu trong MongoDB.
 *
 * Tuong duong bang SQL:
 *   CREATE TABLE jobs (
 *     id uuid PRIMARY KEY,  type, status, payload, processed_rows,
 *     total_rows, attempts, max_attempts, locked_by, heartbeat_at,
 *     error, result_key, created_at, started_at, finished_at
 *   );
 *   CREATE INDEX idx_jobs_claim ON jobs (status, created_at);
 *
 * Ba field bo sung cho hang doi chay duoc an toan:
 *   - `availableAt` : job chua den thoi diem retry se khong bi claim
 *   - `lockedAt`    : thoi diem worker giu job, dung tinh lease het han
 */
@Schema({ collection: 'jobs', timestamps: true })
export class Job {
  /** ULID sinh o application - sap xep theo thu tu thoi gian */
  @Prop({ required: true, unique: true, index: true })
  id!: string;

  @Prop({ required: true })
  type!: string;

  @Prop({ required: true, enum: JOB_STATUSES, default: 'pending' })
  status!: JobStatus;

  /** JSON string trong SQL, o day luu object */
  @Prop({ required: true, type: Object, default: {} })
  payload!: Record<string, unknown>;

  /** checkpoint tien do */
  @Prop({ default: 0 })
  processedRows!: number;

  @Prop({ default: null })
  totalRows?: number | null;

  /** so lan da thu - CHUA tinh lan dang chay */
  @Prop({ default: 0 })
  attempts!: number;

  @Prop({ default: 3 })
  maxAttempts!: number;

  @Prop() lockedBy?: string;
  @Prop() lockedAt?: Date;
  @Prop() lockToken?: string;

  /** nhip tim: worker con song? */
  @Prop() heartbeatAt?: Date;

  @Prop() error?: string;

  /** key ket qua tren object storage */
  @Prop() resultKey?: string;

  /** job chi claim duoc khi da den gio */
  @Prop({ default: () => new Date(), index: true })
  availableAt!: Date;

  @Prop() startedAt?: Date;
  @Prop() finishedAt?: Date;

  /** `timestamps: true` tu sinh - claim sap xep theo `createdAt` tang dan */
  createdAt?: Date;
  updatedAt?: Date;
}

export type JobDocument = HydratedDocument<Job>;
export const JobSchema = SchemaFactory.createForClass(Job);

/**
 * `idx_jobs_claim` - query claim loc theo status roi lay job CU NHAT,
 * nen index dung thu tu cot do giong het SQL.
 */
JobSchema.index({ status: 1, createdAt: 1 });

/** Claim co dieu kien `availableAt <= now` (retry backoff) */
JobSchema.index({ status: 1, availableAt: 1 });

/** Tim job worker dang giu de giu lai lease / huy job orphan */
JobSchema.index({ lockedBy: 1, heartbeatAt: 1 });

/** Dashboard + loc theo loai */
JobSchema.index({ type: 1, createdAt: -1 });
