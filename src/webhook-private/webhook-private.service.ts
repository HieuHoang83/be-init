import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import {
  WebhookPrivateStatus,
  WebhookPrivateEvent,
  WebhookPrivateEventDocument,
} from './webhook-private.entity';
import { WebhookEnvelope } from '../interface/order.interface';
import { extractOrder } from '../core/webhook-payload.util';

export interface RecordPrivateEventInput {
  orgId?: number | null;
  topic: string;
  haravanOrderId?: number | null;
  payload: WebhookEnvelope;
  headers?: Record<string, string>;
  hmacVerified?: boolean;
  haravanRetryCount?: number;
  status?: WebhookPrivateStatus;
  error?: string;
}

export interface ReplayResult {
  queued: boolean;
  jobId: string;
  eventId: string;
  orgId: number;
  haravanOrderId: number;
}

/**
 * Lưu và truy vấn webhook đã nhận. Bản ghi vừa dùng để kiểm tra lịch sử,
 * vừa lưu payload để chạy lại khi xử lý thất bại.
 */
@Injectable()
export class WebhookPrivateService {
  private readonly logger = new Logger(WebhookPrivateService.name);

  constructor(
    @InjectModel(WebhookPrivateEvent.name)
    private readonly eventModel: Model<WebhookPrivateEventDocument>,
  ) {}

  async record(
    input: RecordPrivateEventInput,
  ): Promise<WebhookPrivateEventDocument> {
    const doc = await this.eventModel.create({
      orgId: input.orgId ?? null,
      topic: input.topic,
      haravanOrderId: input.haravanOrderId ?? null,
      payload: input.payload,
      headers: input.headers ?? {},
      hmacVerified: input.hmacVerified ?? true,
      haravanRetryCount: input.haravanRetryCount ?? 0,
      status: input.status ?? WebhookPrivateStatus.RECEIVED,
      error: input.error,
    });

    this.logger.log(
      `Ghi webhook ${doc._id} (${input.topic}, org ${input.orgId ?? 'n/a'}, ` +
        `don ${input.haravanOrderId ?? 'n/a'})`,
    );

    return doc;
  }

  async markStatus(
    eventId: string,
    status: WebhookPrivateStatus,
    extra: { error?: string; jobId?: string } = {},
  ): Promise<void> {
    const update: Record<string, unknown> = { status };
    if (extra.error) update['error'] = extra.error;
    if (extra.jobId) update['jobId'] = extra.jobId;
    if (status === WebhookPrivateStatus.PROCESSED)
      update['processedAt'] = new Date();

    await this.eventModel.updateOne({ _id: eventId }, { $set: update }).exec();
  }

  async findById(eventId: string): Promise<WebhookPrivateEventDocument | null> {
    return this.eventModel.findById(eventId).exec();
  }

  async list(
    filter: Record<string, unknown>,
    page = 1,
    limit = 20,
  ): Promise<{ items: unknown[]; total: number; page: number; limit: number }> {
    const skip = (Math.max(page, 1) - 1) * limit;

    const [items, total] = await Promise.all([
      this.eventModel
        .find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Math.min(limit, 100))
        .exec(),
      this.eventModel.countDocuments(filter).exec(),
    ]);

    return { items, total, page, limit };
  }

  /** Tải đúng payload đã xác thực mà công việc đang tham chiếu. */
  async extractOrderPayload(
    eventId: string,
    orgId: number,
    haravanOrderId: number,
  ): Promise<{ id: number } | null> {
    const event = await this.findById(eventId);
    if (
      !event?.payload ||
      event.orgId !== orgId ||
      event.haravanOrderId !== haravanOrderId
    ) {
      return null;
    }

    try {
      // Dùng header đã lưu để đọc org_id và topic theo định dạng Haravan gửi.
      const { order } = extractOrder(
        (event.headers ?? {}) as Record<string, unknown>,
        event.payload,
      );
      if (order.id !== haravanOrderId) return null;

      // Body co the rong; `extractOrder` khi do dung skeleton `{ id }` tu header.
      // Phai tra null de worker fallback goi Haravan API, neu khong se luu don
      // khong co san pham / tong tien.
      if (!WebhookPrivateService.hasOrderData(order as Record<string, unknown>)) {
        return null;
      }

      return order;
    } catch {
      return null;
    }
  }

  /** Payload co thuc su chua du lieu don hang, hay chi la skeleton `{ id }`. */
  private static hasOrderData(order: Record<string, unknown>): boolean {
    return (
      Array.isArray(order.line_items) ||
      order.financial_status !== undefined ||
      order.fulfillment_status !== undefined ||
      order.confirmed_status !== undefined ||
      order.total_price !== undefined
    );
  }
}
