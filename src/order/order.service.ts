import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { Inject } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { appConfig, RuleConfig } from '../config';
import { extractOrder } from '../core/webhook-payload.util';
import { OrderPayload } from '../interface/order.interface';
import { ApiClient } from '../api/api.service';
import { Customer, CustomerDocument } from './customer.entity';
import {
  ActionResult,
  ActionType,
  Order,
  OrderAction,
  OrderActionDocument,
  OrderDocument,
  OrderStatus,
  SkipReason,
} from './order.entity';

export interface ConfirmDecision {
  shouldConfirm: boolean;
  isReturningCustomer: boolean;
  priorOrderCount: number;
  priorSpent: number;
  skipReason: SkipReason;
}

export interface ProcessResult {
  order: OrderDocument;
  confirmed: boolean;
  decision: ConfirmDecision;
  actionLogId?: Types.ObjectId;
}

export interface UpsertResult {
  created: boolean;
  order: OrderDocument;
}

@Injectable()
export class OrderService {
  private readonly logger = new Logger(OrderService.name);

  private readonly rule: RuleConfig;

  constructor(
    @InjectModel(Order.name) private readonly orderModel: Model<OrderDocument>,
    @InjectModel(Customer.name)
    private readonly customerModel: Model<CustomerDocument>,
    @InjectModel(OrderAction.name)
    private readonly actionModel: Model<OrderActionDocument>,
    private readonly apiClient: ApiClient,
    @Inject(appConfig.KEY) config: ConfigType<typeof appConfig>,
  ) {
    this.rule = config.rule;
  }

  /** Lưu hoặc cập nhật đơn theo shop và ID Haravan. */
  async upsertOrder(
    orgId: number,
    payload: OrderPayload,
    source: 'webhook' | 'api' | 'manual' = 'webhook',
    topic?: string,
  ): Promise<UpsertResult> {
    const isOrderCreatedEvent =
      topic === 'orders/create' || topic === 'orders/created';
    const orderNumber =
      payload.order_number ?? payload.name ?? String(payload.id);
    const orderName =
      payload.name ?? payload.order_number ?? String(payload.id);
    const update: Record<string, unknown> = {
      orderNumber,
      orderName,
      financialStatus: payload.financial_status ?? null,
      fulfillmentStatus: payload.fulfillment_status ?? null,
      confirmedStatus: payload.confirmed_status ?? null,
      cancelledStatus: payload.cancelled_status ?? null,
      closedStatus: payload.closed_status ?? null,
      cancelReason: payload.cancel_reason ?? null,
      gateway: payload.gateway ?? null,
      sourceName: payload.source_name ?? null,
      totalPrice: payload.total_price ?? 0,
      subtotalPrice: payload.subtotal_price ?? 0,
      totalTax: payload.total_tax ?? 0,
      totalDiscounts: payload.total_discounts ?? 0,
      currency: payload.currency ?? 'VND',
      itemCount: (payload.line_items ?? []).reduce(
        (sum, li) => sum + (li?.quantity ?? 0),
        0,
      ),
      lineItems: payload.line_items ?? [],
      shippingAddress: payload.shipping_address ?? undefined,
      billingAddress: payload.billing_address ?? undefined,
      payload,
      lastWebhookAt: new Date(),
      lastWebhookTopic: topic,
    };

    const already = await this.orderModel
      .findOne({ orgId, haravanOrderId: payload.id })
      .select('status')
      .lean()
      .exec();
    if (!already || already.status !== OrderStatus.CONFIRMED) {
      update['status'] = OrderStatus.PENDING;
    }

    for (const [field, value] of Object.entries(
      this.buildCustomerPatch(payload, isOrderCreatedEvent),
    )) {
      if (value !== undefined) update[field] = value;
    }

    const doc = await this.orderModel
      .findOneAndUpdate(
        { orgId, haravanOrderId: payload.id },
        { $set: update, $setOnInsert: { orgId, haravanOrderId: payload.id } },
        { upsert: true, new: true, setDefaultsOnInsert: true },
      )
      .exec();

    this.logger.log(
      `Luu don ${orderNumber} (org ${orgId}, source ${source}): ` +
        `${payload.financial_status ?? 'n/a'} / ${
          doc.confirmedStatus ?? 'unconfirmed'
        }`,
    );

    return { created: true, order: doc };
  }

  /** Chỉ cập nhật các trường khách hàng có dữ liệu. */
  private buildCustomerPatch(
    payload: OrderPayload,
    includeCreationSnapshot: boolean,
  ): Record<string, unknown> {
    const c = payload.customer;
    if (!c) return {};

    const fullName =
      (payload.shipping_address?.name ?? '').trim() ||
      [c.first_name, c.last_name].filter(Boolean).join(' ').trim() ||
      undefined;

    const patch: Record<string, unknown> = {
      'customer.email': this.orNull(c.email?.toLowerCase()),
      'customer.phone': this.orNull(
        OrderService.normalizePhone(c.phone ?? payload.shipping_address?.phone),
      ),
      'customer.totalSpent': this.orNull(c.total_spent),
      'customer.totalPaid': this.orNull(c.total_paid),
      'customer.state': this.orNull(c.state),
      'customer.verifiedEmail': this.orNull(c.verified_email),
      'customer.lastOrderId': this.orNull(c.last_order_id),
      'customer.lastOrderName': this.orNull(c.last_order_name),
    };
    if (includeCreationSnapshot && c.orders_count != null) {
      patch['customer.ordersCount'] = c.orders_count;
    }

    if (c.first_name) patch['customer.firstName'] = c.first_name;
    if (c.last_name) patch['customer.lastName'] = c.last_name;
    if (fullName) patch['customer.fullName'] = fullName;
    if (c.id) patch['customer.haravanId'] = c.id;

    const orderPhone = OrderService.normalizePhone(
      c.phone ?? payload.shipping_address?.phone,
    );
    if (orderPhone) patch['phone'] = orderPhone;
    if (c.email) patch['email'] = c.email.toLowerCase();
    if (fullName) patch['customerName'] = fullName;

    return patch;
  }

  private orNull<T>(value: T | null | undefined): T | null {
    return value === undefined || value === null ? null : value;
  }

  /** Chuẩn hóa số điện thoại để so khớp khách hàng. */
  private static normalizePhone(raw?: string | null): string | undefined {
    if (!raw) return undefined;
    const digits = String(raw).replace(/\D/g, '');
    if (!digits) return undefined;
    const local = digits.replace(/^84/, '0').replace(/^0+/, '0');
    return local.length >= 9 && local.length <= 15 ? local : undefined;
  }

  /** Lưu hoặc cập nhật khách khi có ID, số điện thoại hoặc email. */
  async upsertCustomer(
    orgId: number,
    payload: OrderPayload,
    topic?: string,
  ): Promise<void> {
    const isOrderCreatedEvent =
      topic === 'orders/create' || topic === 'orders/created';
    const c = payload.customer;
    if (!c) return;

    const phone = OrderService.normalizePhone(
      c.phone ?? payload.shipping_address?.phone,
    );
    const email = c.email?.trim().toLowerCase() || undefined;
    const haravanCustomerId = c.id ?? undefined;

    if (!phone && !email && !haravanCustomerId) return;

    const fullName =
      (payload.shipping_address?.name ?? '').trim() ||
      [c.first_name, c.last_name].filter(Boolean).join(' ').trim() ||
      undefined;

    const or: Record<string, unknown>[] = [];
    if (haravanCustomerId) or.push({ haravanCustomerId });
    if (phone) or.push({ phone });
    if (email) or.push({ email });

    const existing = await this.customerModel
      .findOne({ orgId, $or: or })
      .lean()
      .exec();

    const patch: Record<string, unknown> = {
      orgId,
      lastSeenAt: new Date(),
      lastOrderId: c.last_order_id ?? payload.id,
      lastOrderName: c.last_order_name ?? payload.order_number ?? undefined,
    };

    if (haravanCustomerId) patch['haravanCustomerId'] = haravanCustomerId;
    if (phone) patch['phone'] = phone;
    if (email) patch['email'] = email;
    if (fullName) patch['fullName'] = fullName;
    if (c.first_name) patch['firstName'] = c.first_name;
    if (c.last_name) patch['lastName'] = c.last_name;
    if (c.state) patch['state'] = c.state;
    if (typeof c.verified_email === 'boolean')
      patch['verifiedEmail'] = c.verified_email;
    if (isOrderCreatedEvent && c.orders_count != null) {
      patch['haravanOrdersCount'] = c.orders_count;
    }

    if (existing) {
      await this.customerModel
        .updateOne(
          { _id: existing._id },
          { $set: patch, $addToSet: { orderIds: payload.id } },
        )
        .exec();
      return;
    }

    await this.customerModel.create({
      ...patch,
      firstSeenAt: new Date(),
      orderIds: [payload.id],
      infoSourceOrderId: payload.id,
      infoSourceTopic: topic,
      beOrderCount: 1,
      beTotalSpent: payload.total_price ?? 0,
      haravanOrdersCount:
        isOrderCreatedEvent && c.orders_count != null ? c.orders_count : 0,
      haravanTotalSpent: c.total_spent ?? 0,
    });

    this.logger.log(
      `Khach moi ${fullName ?? '(chua co ten)'} / ${
        phone ?? email ?? 'khong co khoa'
      }` + ` (don ${payload.order_number ?? payload.id})`,
    );
  }

  /** Đếm đơn trước của khách, bỏ đơn hiện tại và đơn đã hủy. */
  async countPriorOrders(
    orgId: number,
    order: OrderDocument,
  ): Promise<{ priorOrderCount: number; priorSpent: number }> {
    const cust = order.customer;

    const phone =
      OrderService.normalizePhone(cust?.phone) ??
      OrderService.normalizePhone(order.phone);
    const email = (cust?.email ?? order.email)?.trim().toLowerCase();

    const or: Record<string, unknown>[] = [];
    if (cust?.haravanId) or.push({ 'customer.haravanId': cust.haravanId });
    if (phone) or.push({ phone });
    if (email) or.push({ email: email });
    if (!or.length) return { priorOrderCount: 0, priorSpent: 0 };

    const filter: Record<string, unknown> = {
      orgId,
      status: { $ne: OrderStatus.CANCELLED },
      haravanOrderId: { $ne: order.haravanOrderId },
      $or: or,
    };

    const [count, agg] = await Promise.all([
      this.orderModel.countDocuments(filter).exec(),
      this.orderModel
        .aggregate<{ total: number }>([
          { $match: filter },
          { $group: { _id: null, total: { $sum: '$totalPrice' } } },
        ])
        .exec(),
    ]);

    return { priorOrderCount: count, priorSpent: agg[0]?.total ?? 0 };
  }

  /** Kiểm tra đơn có đủ điều kiện xác nhận không. */
  async evaluateConfirmEligibility(
    orgId: number,
    order: OrderDocument,
  ): Promise<ConfirmDecision> {
    const skip = (reason: SkipReason, priorOrderCount = 0, priorSpent = 0) => ({
      shouldConfirm: false,
      isReturningCustomer: false,
      priorOrderCount,
      priorSpent,
      skipReason: reason,
    });

    if (
      !order.customer?.haravanId &&
      !order.customer?.email &&
      !order.customer?.phone &&
      !order.phone
    ) {
      return skip(SkipReason.NO_CUSTOMER);
    }

    if (
      order.cancelledStatus === 'cancelled' ||
      order.closedStatus === 'closed'
    ) {
      return skip(SkipReason.ORDER_CANCELLED);
    }

    if (order.confirmedStatus === 'confirmed') {
      return skip(SkipReason.ALREADY_CONFIRMED);
    }

    const { priorOrderCount, priorSpent } = await this.countPriorOrders(
      orgId,
      order,
    );

    const isReturningCustomer = priorOrderCount >= this.rule.minPriorOrders;

    if (priorOrderCount < this.rule.minPriorOrders) {
      return {
        shouldConfirm: false,
        isReturningCustomer: false,
        priorOrderCount,
        priorSpent,
        skipReason:
          priorOrderCount === 0
            ? SkipReason.FIRST_TIME_BUYER
            : SkipReason.NOT_ENOUGH_PRIOR_ORDERS,
      };
    }

    if (this.rule.minPriorSpent > 0 && priorSpent < this.rule.minPriorSpent) {
      return {
        shouldConfirm: false,
        isReturningCustomer: true,
        priorOrderCount,
        priorSpent,
        skipReason: SkipReason.NOT_ENOUGH_PRIOR_SPENT,
      };
    }

    return {
      shouldConfirm: true,
      isReturningCustomer: true,
      priorOrderCount,
      priorSpent,
      skipReason: SkipReason.NONE,
    };
  }

  /** Lưu đơn, kiểm tra rule và xác nhận nếu đủ điều kiện. */
  async processIncomingOrder(params: {
    orgId: number;
    payload: OrderPayload;
    source?: 'webhook' | 'api' | 'manual';
    jobId?: string;
    topic?: string;
  }): Promise<ProcessResult> {
    const { orgId, payload, source = 'webhook', jobId, topic } = params;

    const { order } = await this.upsertOrder(orgId, payload, source, topic);
    await this.upsertCustomer(orgId, payload, topic);
    order.status = OrderStatus.PROCESSING;
    order.processing = { ...order.processing, source, jobId };
    await order.save();

    const decision = await this.evaluateConfirmEligibility(orgId, order);

    await this.logAction(
      orgId,
      payload.id,
      ActionType.EVALUATE,
      ActionResult.SUCCESS,
      {
        reason: decision.skipReason,
        message:
          `priorOrderCount=${decision.priorOrderCount}, ` +
          `priorSpent=${decision.priorSpent}, ` +
          `minPriorOrders=${this.rule.minPriorOrders}`,
        manual: false,
      },
    );

    if (!decision.shouldConfirm) {
      order.status =
        decision.skipReason === SkipReason.ORDER_CANCELLED
          ? OrderStatus.CANCELLED
          : OrderStatus.SKIPPED;
      order.processing = {
        reason: decision.skipReason,
        isReturningCustomer: decision.isReturningCustomer,
        priorOrderCount: decision.priorOrderCount,
        priorSpent: decision.priorSpent,
        source,
        jobId,
      };
      await order.save();

      this.logger.log(
        `Bo qua xac nhan don ${payload.id}: ${decision.skipReason} ` +
          `(prior=${decision.priorOrderCount})`,
      );

      return { order, confirmed: false, decision };
    }

    const confirmed = await this.confirmOrder({
      orgId,
      haravanOrderId: payload.id,
      manual: false,
      actor: 'system',
      source,
    });

    return {
      order: confirmed.order,
      confirmed: true,
      decision,
      actionLogId: confirmed.actionLogId,
    };
  }

  /** Xác nhận đơn; `force` bỏ qua rule khi admin xác nhận thủ công. */
  async confirmOrder(params: {
    orgId: number;
    haravanOrderId: number;
    manual?: boolean;
    actor?: string;
    force?: boolean;
    source?: 'webhook' | 'api' | 'manual';
  }): Promise<ProcessResult> {
    const {
      orgId,
      haravanOrderId,
      manual = false,
      actor,
      force = false,
      source,
    } = params;

    const order = await this.findOrderById(orgId, haravanOrderId);
    if (!order) {
      throw new NotFoundException(
        `Khong tim thay don ${haravanOrderId} cua org ${orgId}`,
      );
    }

    const decision = force
      ? {
          shouldConfirm: true,
          isReturningCustomer: order.processing?.isReturningCustomer ?? false,
          priorOrderCount: order.processing?.priorOrderCount ?? 0,
          priorSpent: order.processing?.priorSpent ?? 0,
          skipReason: SkipReason.NONE,
        }
      : await this.evaluateConfirmEligibility(orgId, order);

    if (!decision.shouldConfirm) {
      order.status = OrderStatus.SKIPPED;
      order.processing = { ...order.processing, ...toProcessing(decision) };
      await order.save();

      await this.logAction(
        orgId,
        haravanOrderId,
        ActionType.CONFIRM_FAILED,
        ActionResult.SKIPPED,
        { reason: decision.skipReason, manual, actor },
      );

      return { order, confirmed: false, decision };
    }

    await this.logAction(
      orgId,
      haravanOrderId,
      ActionType.CONFIRM_SEND,
      ActionResult.SUCCESS,
      {
        manual,
        actor,
        message: `force=${force}`,
      },
    );

    const startedAt = Date.now();
    try {
      const res = await this.apiClient.confirmOrder(orgId, haravanOrderId);

      order.status = OrderStatus.CONFIRMED;
      order.confirmedStatus = 'confirmed';
      order.processing = { ...order.processing, ...toProcessing(decision) };
      await order.save();

      const actionLogId = await this.logAction(
        orgId,
        haravanOrderId,
        ActionType.CONFIRM_SUCCESS,
        ActionResult.SUCCESS,
        {
          manual,
          actor,
          apiCall: {
            method: 'POST',
            url: `/orders/${haravanOrderId}/confirm.json`,
            requestBody: { confirmed_status: 'confirmed' },
            statusCode: res.statusCode,
            responseBody: res.body as Record<string, unknown>,
            durationMs: Date.now() - startedAt,
          },
        },
      );

      this.logger.log(`Da xac nhan don ${haravanOrderId} (org ${orgId})`);

      return { order, confirmed: true, decision, actionLogId };
    } catch (error) {
      const message = (error as Error).message;

      order.status = OrderStatus.FAILED;
      order.processing = {
        ...order.processing,
        ...toProcessing(decision),
        reason: SkipReason.CONFIRM_ERROR,
        error: message,
      };
      await order.save();

      await this.logAction(
        orgId,
        haravanOrderId,
        ActionType.CONFIRM_FAILED,
        ActionResult.FAILED,
        {
          manual,
          actor,
          reason: SkipReason.CONFIRM_ERROR,
          message,
          apiCall: {
            url: `/orders/${haravanOrderId}/confirm.json`,
            durationMs: Date.now() - startedAt,
          },
        },
      );

      this.logger.error(`Xac nhan don ${haravanOrderId} that bai: ${message}`);
      throw error;
    }
  }

  /** Lấy đơn từ API nếu không còn payload webhook. */
  async fetchOrderFromApi(
    orgId: number,
    haravanOrderId: number,
  ): Promise<OrderPayload> {
    const res = await this.apiClient.getOrder(orgId, haravanOrderId);
    return res.body;
  }

  async findOrderById(
    orgId: number,
    haravanOrderId: number,
  ): Promise<OrderDocument | null> {
    return this.orderModel.findOne({ orgId, haravanOrderId }).exec();
  }

  async findOrders(
    filter: Record<string, unknown>,
    page = 1,
    limit = 20,
  ): Promise<{ items: unknown[]; total: number; page: number; limit: number }> {
    const skip = (Math.max(page, 1) - 1) * limit;

    const [items, total] = await Promise.all([
      this.orderModel
        .find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Math.min(limit, 100))
        .exec(),
      this.orderModel.countDocuments(filter).exec(),
    ]);

    const rows = await this.attachCustomerHistory(items);

    return { items: rows, total, page, limit };
  }

  /** Bổ sung tên đơn và lịch sử mua của khách vào danh sách. */
  private async attachCustomerHistory(
    items: OrderDocument[],
  ): Promise<unknown[]> {
    if (!items.length) return [];

    return Promise.all(
      items.map(async (order) => {
        const doc = order.toObject() as unknown as Record<string, unknown>;
        const processing = (doc['processing'] ?? {}) as Record<string, unknown>;
        const hasCustomerIdentity = Boolean(
          order.customer?.haravanId ||
            order.customer?.email?.trim() ||
            order.customer?.phone?.trim() ||
            order.email?.trim() ||
            order.phone?.trim(),
        );
        const name =
          order.orderName ??
          order.orderNumber ??
          String(order.haravanOrderId);
        const payloadOrderNumber = Number(order.customer?.ordersCount);

        if (typeof processing['isReturningCustomer'] === 'boolean') {
          const priorOrderCount = Number(
            processing['priorOrderCount'] ?? 0,
          );
          return {
            ...doc,
            name,
            isReturningCustomer: processing['isReturningCustomer'],
            priorOrderCount,
            priorSpent: processing['priorSpent'] ?? 0,
            customerOrderNumber:
              Number.isInteger(payloadOrderNumber) && payloadOrderNumber > 0
                ? payloadOrderNumber
                : hasCustomerIdentity
                  ? priorOrderCount + 1
                  : null,
          };
        }

        const { priorOrderCount } = await this.countPriorOrders(
          order.orgId,
          order,
        );
        const isReturning = priorOrderCount > 0;

        return {
          ...doc,
          name,
          isReturningCustomer: isReturning,
          priorOrderCount,
          priorSpent: processing['priorSpent'] ?? 0,
          customerOrderNumber:
            Number.isInteger(payloadOrderNumber) && payloadOrderNumber > 0
              ? payloadOrderNumber
              : hasCustomerIdentity
                ? priorOrderCount + 1
                : null,
        };
      }),
    );
  }

  async findActions(
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

  async getStats(orgId?: number): Promise<Record<string, unknown>> {
    const match = orgId ? { orgId } : {};

    const [byStatus] = await this.orderModel.aggregate([
      { $match: match },
      { $group: { _id: '$status', count: { $sum: 1 } } },
    ]);

    const [totals] = await this.orderModel.aggregate([
      { $match: match },
      {
        $group: {
          _id: null,
          totalOrders: { $sum: 1 },
          totalRevenue: { $sum: '$totalPrice' },
          confirmedRevenue: {
            $sum: {
              $cond: [
                { $eq: ['$status', OrderStatus.CONFIRMED] },
                '$totalPrice',
                0,
              ],
            },
          },
        },
      },
    ]);

    return {
      byStatus: byStatus ?? {},
      totalOrders: totals?.totalOrders ?? 0,
      totalRevenue: totals?.totalRevenue ?? 0,
      confirmedRevenue: totals?.confirmedRevenue ?? 0,
    };
  }

  private async logAction(
    orgId: number,
    haravanOrderId: number,
    type: ActionType,
    result: ActionResult,
    extra: {
      manual?: boolean;
      actor?: string;
      reason?: SkipReason;
      message?: string;
      attempt?: number;
      apiCall?: Record<string, unknown>;
    } = {},
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

  /** Tìm đơn để chạy lại webhook lỗi. */
  async requireOrder(
    orgId: number,
    haravanOrderId: number,
  ): Promise<OrderDocument> {
    const order = await this.findOrderById(orgId, haravanOrderId);
    if (!order) {
      throw new BadRequestException(
        `Don ${haravanOrderId} chua duoc luu, khong the xu lai`,
      );
    }
    return order;
  }
}

function toProcessing(decision: ConfirmDecision) {
  return {
    reason: decision.skipReason,
    isReturningCustomer: decision.isReturningCustomer,
    priorOrderCount: decision.priorOrderCount,
    priorSpent: decision.priorSpent,
  };
}
