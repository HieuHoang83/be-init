import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import {
  ActionResult,
  ActionType,
  OrderAction,
  OrderActionDocument,
  OrderEvent,
  OrderEventAction,
  OrderEventDocument,
  OrderEventSource,
  SkipReason,
} from '../entities/order.entity';

/** Thông tin bổ sung khi ghi một lần gọi API vào nhật ký kỹ thuật. */
export interface ActionLogExtra {
  manual?: boolean;
  actor?: string;
  reason?: SkipReason;
  message?: string;
  attempt?: number;
  apiCall?: Record<string, unknown>;
}

/** Thông tin một sự kiện nghiệp vụ hiển thị cho người dùng. */
export interface OrderEventInput {
  orgId: number;
  haravanOrderId: number;
  action: OrderEventAction;
  source: OrderEventSource;
  description: string;
  changedFields?: string[];
  actor?: string;
  topic?: string;
}

/**
 * Ghi và đọc hai loại nhật ký của đơn hàng:
 * - `order_actions`: log kỹ thuật (mỗi lần gọi API, kết quả, thời gian) — dùng để debug.
 * - `order_events`: log nghiệp vụ (đã hủy, đã hoàn tiền...) — dùng cho timeline trên UI.
 */
@Injectable()
export class OrderAuditService {
  constructor(
    @InjectModel(OrderAction.name)
    private readonly actionModel: Model<OrderActionDocument>,
    @InjectModel(OrderEvent.name)
    private readonly eventModel: Model<OrderEventDocument>,
  ) {}

  async logAction(
    orgId: number,
    haravanOrderId: number,
    type: ActionType,
    result: ActionResult,
    extra: ActionLogExtra = {},
  ): Promise<Types.ObjectId> {
    const doc = await this.actionModel.create({
      orgId,
      haravanOrderId,
      type,
      result,
      manual: extra.manual ?? false,
      actor: extra.actor,
      reason: extra.reason,
      message: extra.message,
      attempt: extra.attempt ?? 1,
      apiCall: extra.apiCall,
    });
    return doc._id;
  }

  async logOrderEvent(event: OrderEventInput): Promise<void> {
    await this.eventModel.create({
      ...event,
      changedFields: event.changedFields ?? [],
    });
  }

  findActions(
    orgId: number,
    haravanOrderId: number,
    limit = 100,
  ): Promise<unknown[]> {
    return this.actionModel
      .find({ orgId, haravanOrderId })
      .sort({ createdAt: -1 })
      .limit(limit)
      .exec();
  }

  findEvents(
    orgId: number,
    haravanOrderId: number,
    limit = 100,
  ): Promise<OrderEventDocument[]> {
    return this.eventModel
      .find({ orgId, haravanOrderId })
      .sort({ createdAt: -1 })
      .limit(limit)
      .exec();
  }
}
