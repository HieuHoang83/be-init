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
  /** org_id tu Harovan, null neu payload khong hop le */
  @Prop({ index: true })
  orgId?: number | null;

  @Prop({ required: true, index: true })
  topic!: string;

  @Prop({ index: true })
  haravanOrderId?: number | null;

  /** HMAC da verify thanh cong truoc khi luu */
  @Prop({ default: true })
  hmacVerified!: boolean;

  @Prop({ default: 0 })
  haravanRetryCount?: number;

  @Prop({ type: String, enum: WebhookPrivateStatus, default: WebhookPrivateStatus.RECEIVED, index: true })
  status!: WebhookPrivateStatus;

  @Prop() error?: string;

  /** Chi luu header can cho audit, khong luu secret */
  @Prop({ type: Object })
  headers?: Record<string, string>;

  /** Payload goc, dung de replay */
  @Prop({ type: Object })
  payload!: WebhookEnvelope;

  @Prop()
  jobId?: string;

  @Prop()
  processedAt?: Date;
}
export type WebhookPrivateEventDocument = HydratedDocument<WebhookPrivateEvent>;

export const WebhookPrivateEventSchema = SchemaFactory.createForClass(WebhookPrivateEvent);

WebhookPrivateEventSchema.index({ orgId: 1, createdAt: -1 });
WebhookPrivateEventSchema.index({ topic: 1, createdAt: -1 });
