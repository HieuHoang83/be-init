import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';
import { WebhookEnvelope } from '../interface/order.interface';

export enum WebhookPrivateStatus {
  RECEIVED = 'received',
  QUEUED = 'queued',
  PROCESSING = 'processing',
  PROCESSED = 'processed',
  IGNORED = 'ignored',
  INVALID = 'invalid',
  FAILED = 'failed',
}

@Schema({ collection: 'webhook_events', timestamps: true })
export class WebhookPrivateEvent {
  /** org_id do Haravan gửi; null nếu payload không hợp lệ. */
  @Prop({ index: true })
  orgId?: number | null;

  @Prop({ required: true, index: true })
  topic!: string;

  @Prop({ index: true })
  haravanOrderId?: number | null;

  /** Cho biết HMAC đã được xác thực trước khi lưu. */
  @Prop({ default: true })
  hmacVerified!: boolean;

  @Prop({ default: 0 })
  haravanRetryCount?: number;

  @Prop({
    type: String,
    enum: WebhookPrivateStatus,
    default: WebhookPrivateStatus.RECEIVED,
    index: true,
  })
  status!: WebhookPrivateStatus;

  @Prop() error?: string;

  /** Chỉ lưu header cần kiểm tra; không lưu secret. */
  @Prop({ type: Object })
  headers?: Record<string, string>;

  /** Payload gốc dùng để chạy lại sự kiện. */
  @Prop({ type: Object })
  payload!: WebhookEnvelope;

  @Prop()
  jobId?: string;

  @Prop()
  processedAt?: Date;
}
export type WebhookPrivateEventDocument = HydratedDocument<WebhookPrivateEvent>;

export const WebhookPrivateEventSchema =
  SchemaFactory.createForClass(WebhookPrivateEvent);

WebhookPrivateEventSchema.index({ orgId: 1, createdAt: -1 });
WebhookPrivateEventSchema.index({ topic: 1, createdAt: -1 });
