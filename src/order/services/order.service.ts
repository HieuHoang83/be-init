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
import { appConfig, RuleConfig } from '../../config';
import { extractOrder } from '../../core/webhook-payload.util';
import { OrderPayload } from '../../interface/order.interface';
import { hasRealCustomerIdentity } from '../utils/customer-identity.util';
import { ApiClient } from '../../api/api.service';
import { CreateOrderBody } from '../dto/order.dto';
import { Customer, CustomerDocument } from '../entities/customer.entity';
import {
  ActionResult,
  ActionType,
  Order,
  OrderAction,
  OrderActionDocument,
  OrderDocument,
  OrderEvent,
  OrderEventAction,
  OrderEventDocument,
  OrderEventSource,
  OrderStatus,
  SkipReason,
} from '../entities/order.entity';
import { ConfirmDecision, decideConfirm } from '../rules/order.rules';
import { OrderAuditService } from './order-audit.service';
import {
  buildCustomerPatch,
  changedOrderFields,
  mergeOrderPayload,
  normalizePhone,
  resolveFullName,
  resolveHaravanOrderStatus,
  toProcessing,
} from '../mappers/order.mapper';

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
    private readonly audit: OrderAuditService,
    private readonly apiClient: ApiClient,
    @Inject(appConfig.KEY) config: ConfigType<typeof appConfig>,
  ) {
    this.rule = config.rule;
  }

  /** Create an order in Haravan and immediately mirror its response locally. */
  async createOrder(orgId: number, body: CreateOrderBody) {
    const {
      first_name,
      last_name,
      address1,
      city,
      province,
      country,
      customer_id,
      ...orderFields
    } = body;
    const hasAddress = Boolean(
      address1 || city || province || country,
    );

    const requestedQuantities = new Map<number, number>();
    const variantPricing = new Map<number, { price: number; productId?: number }>();
    for (const item of body.line_items) {
      if (item.variant_id === undefined) continue;
      requestedQuantities.set(
        item.variant_id,
        (requestedQuantities.get(item.variant_id) ?? 0) + item.quantity,
      );
    }
    await Promise.all(
      [...requestedQuantities].map(async ([variantId, requestedQuantity]) => {
        const response = await this.apiClient.call<{
          variant?: {
            sku?: string | null;
            title?: string | null;
            price?: number | string | null;
            product_id?: number | null;
            inventory_management?: string | null;
            inventory_policy?: string | null;
            inventory_quantity?: number | null;
            inventory_advance?: { qty_available?: number | null } | null;
          };
        }>(orgId, 'GET', `/variants/${variantId}.json`);
        const variant = response.body?.variant;
        if (!variant) {
          throw new BadRequestException(
            `Khong tim thay bien the ${variantId} tren Haravan`,
          );
        }
        variantPricing.set(variantId, {
          price: Number(variant.price ?? 0),
          productId: variant.product_id ?? undefined,
        });
        if (
          !variant.inventory_management ||
          variant.inventory_policy === 'continue'
        ) {
          return;
        }
        const available =
          variant.inventory_advance?.qty_available ??
          variant.inventory_quantity ??
          0;
        if (requestedQuantity > available) {
          const name = variant.sku || variant.title || String(variantId);
          throw new BadRequestException(
            `Bien the ${name} chi con ${available} san pham kha dung`,
          );
        }
      }),
    );

    let discountCodes = body.discount_codes;
    const coupon = body.discount_codes?.find((discount) => discount.is_coupon_code);
    if (coupon) {
      const discountResponse = await this.apiClient.call<{
        discounts?: Array<{
          code?: string;
          status?: string;
          starts_at?: string | null;
          ends_at?: string | null;
          value?: number | string | null;
          discount_type?: string | null;
          applies_once?: boolean;
          minimum_order_amount?: number | string | null;
          max_amount_apply?: number | string | null;
        }>;
      }>(orgId, 'GET', '/discounts.json', undefined, { code: coupon.code });
      const definition = discountResponse.body?.discounts?.find(
        (item) => item.code?.toLocaleLowerCase() === coupon.code.toLocaleLowerCase(),
      );
      if (!definition || definition.status !== 'enabled') {
        throw new BadRequestException('Ma khuyen mai khong ton tai hoac da tat');
      }
      const now = Date.now();
      if (
        (definition.starts_at && new Date(definition.starts_at).getTime() > now) ||
        (definition.ends_at && new Date(definition.ends_at).getTime() <= now)
      ) {
        throw new BadRequestException('Ma khuyen mai chua bat dau hoac da het han');
      }
      const subtotal = body.line_items.reduce((sum, item) => {
        const unitPrice = item.variant_id !== undefined
          ? variantPricing.get(item.variant_id)?.price ?? Number(item.price ?? 0)
          : Number(item.price ?? 0);
        return sum + unitPrice * item.quantity;
      }, 0);
      const minimum = Number(definition.minimum_order_amount ?? 0);
      if (subtotal < minimum) {
        throw new BadRequestException(
          `Don hang chua dat gia tri toi thieu ${minimum} de ap dung ma khuyen mai`,
        );
      }
      const value = Number(definition.value ?? 0);
      const itemCount = body.line_items.reduce((sum, item) => sum + item.quantity, 0);
      let amount = definition.discount_type === 'percentage'
        ? Math.round(subtotal * value / 100)
        : definition.discount_type === 'fixed_amount'
          ? value * (definition.applies_once === false ? itemCount : 1)
          : 0;
      const maximum = Number(definition.max_amount_apply ?? 0);
      if (maximum > 0) amount = Math.min(amount, maximum);
      amount = Math.min(Math.max(0, Math.round(amount)), Math.round(subtotal));
      if (!amount) {
        throw new BadRequestException('Ma khuyen mai khong tao ra muc giam gia hop le');
      }
      discountCodes = body.discount_codes?.map((discount) =>
        discount === coupon ? { ...discount, amount } : discount,
      );
    }

    const customLineDiscount = body.line_items.reduce(
      (sum, item) => sum + Number(item.total_discount ?? 0),
      0,
    );
    const manualDiscountCode = body.discount_codes?.find(
      (discount) => !discount.is_coupon_code,
    );
    const totalDiscounts = coupon ? 0 : manualDiscountCode?.amount ?? customLineDiscount;

    const response = await this.apiClient.call<{ order?: OrderPayload }>(
      orgId,
      'POST',
      '/orders.json',
      {
        order: {
          ...orderFields,
          ...(discountCodes ? { discount_codes: discountCodes } : {}),
          ...(totalDiscounts > 0 ? { total_discounts: totalDiscounts } : {}),
          financial_status: body.financial_status ?? 'pending',
          ...(body.financial_status === 'paid'
            ? { transactions: [{ kind: 'capture' }] }
            : {}),
          ...(customer_id ? { customer: { id: customer_id } } : {}),
          ...(hasAddress
            ? {
                shipping_address: {
                  first_name,
                  last_name,
                  address1,
                  city,
                  province,
                  country: country || 'Vietnam',
                  phone: body.phone,
                },
              }
            : {}),
        },
      },
    );
    const payload = response.body?.order;
    if (!payload?.id) {
      throw new BadRequestException('Haravan khong tra ve thong tin don hang');
    }
    // Haravan đôi khi chỉ trả customer.id khi tạo order bằng customer reference.
    // Giữ snapshot từ khách đã chọn để UI hiển thị đúng mà không cần tạo shipping address.
    const snapshotFirstName = payload.customer?.first_name ?? first_name;
    const snapshotLastName = payload.customer?.last_name ?? last_name;
    const snapshotEmail = payload.customer?.email ?? body.email;
    const snapshotPhone = payload.customer?.phone ?? body.phone;
    const customerSnapshot = payload.customer || customer_id || snapshotFirstName || snapshotLastName || snapshotEmail || snapshotPhone
      ? {
          ...(payload.customer ?? {}),
          ...(customer_id ? { id: customer_id } : {}),
          ...(snapshotFirstName ? { first_name: snapshotFirstName } : {}),
          ...(snapshotLastName ? { last_name: snapshotLastName } : {}),
          ...(snapshotEmail ? { email: snapshotEmail } : {}),
          ...(snapshotPhone ? { phone: snapshotPhone } : {}),
        }
      : undefined;
    const orderPayload: OrderPayload = {
      ...payload,
      ...(payload.email ?? body.email ? { email: payload.email ?? body.email } : {}),
      ...(payload.phone ?? body.phone ? { phone: payload.phone ?? body.phone } : {}),
      ...(customerSnapshot ? { customer: customerSnapshot } : {}),
    };
    const result = await this.upsertOrder(orgId, orderPayload, 'api');
    return result.order;
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
    const existing = await this.orderModel
      .findOne({ orgId, haravanOrderId: payload.id })
      .select(
        'status orderName orderNumber customerName email phone financialStatus fulfillmentStatus confirmedStatus haravanStatus gateway sourceName totalPrice subtotalPrice totalTax totalDiscounts itemCount lineItems shippingAddress billingAddress payload',
      )
      .lean()
      .exec();
    const effectivePayload = mergeOrderPayload(
      existing?.payload,
      payload,
      source === 'api' && Boolean(existing),
    );
    const haravanName = payload.name?.trim();
    const orderNumber =
      payload.order_number?.trim() ||
      existing?.orderNumber ||
      haravanName ||
      String(payload.id);
    const orderName =
      haravanName ||
      existing?.orderName ||
      payload.order_number?.trim() ||
      String(payload.id);
    const update: Record<string, unknown> = {
      orderNumber,
      orderName,
      payload: effectivePayload,
      lastWebhookAt: new Date(),
    };

    const hasField = (field: keyof OrderPayload) =>
      Object.prototype.hasOwnProperty.call(payload, field);
    const setWhenPresent = (
      sourceField: keyof OrderPayload,
      targetField: string,
      value: unknown = effectivePayload[sourceField],
    ) => {
      if (
        hasField(sourceField) &&
        !(source === 'api' && existing && payload[sourceField] == null)
      ) {
        update[targetField] = value;
      }
    };
    const lifecycleFields: Array<keyof OrderPayload> = [
      'status',
      'cancelled_status',
      'closed_status',
      'cancelled_at',
      'closed_at',
    ];
    if (
      lifecycleFields.some((field) =>
        Object.prototype.hasOwnProperty.call(effectivePayload, field),
      )
    ) {
      const haravanStatus = resolveHaravanOrderStatus(effectivePayload);
      if (haravanStatus !== null || lifecycleFields.some(hasField)) {
        update['haravanStatus'] = haravanStatus;
      }
    }
    setWhenPresent('financial_status', 'financialStatus');
    setWhenPresent('fulfillment_status', 'fulfillmentStatus');
    setWhenPresent('confirmed_status', 'confirmedStatus');
    setWhenPresent('cancelled_status', 'cancelledStatus');
    setWhenPresent('closed_status', 'closedStatus');
    setWhenPresent('cancel_reason', 'cancelReason');
    setWhenPresent('gateway', 'gateway');
    setWhenPresent('source_name', 'sourceName');
    setWhenPresent('total_price', 'totalPrice', payload.total_price ?? 0);
    setWhenPresent(
      'subtotal_price',
      'subtotalPrice',
      payload.subtotal_price ?? 0,
    );
    setWhenPresent('total_tax', 'totalTax', payload.total_tax ?? 0);
    setWhenPresent(
      'total_discounts',
      'totalDiscounts',
      payload.total_discounts ?? 0,
    );
    setWhenPresent('currency', 'currency', payload.currency ?? 'VND');
    if (hasField('line_items')) {
      const lineItems = payload.line_items ?? [];
      update['itemCount'] = lineItems.reduce(
        (sum, lineItem) => sum + (lineItem?.quantity ?? 0),
        0,
      );
      update['lineItems'] = lineItems;
    }
    setWhenPresent('shipping_address', 'shippingAddress');
    setWhenPresent('billing_address', 'billingAddress');
    if (topic !== undefined) update['lastWebhookTopic'] = topic;

    if (!existing || existing.status !== OrderStatus.CONFIRMED) {
      update['status'] = OrderStatus.PENDING;
    }

    for (const [field, value] of Object.entries(
      buildCustomerPatch(effectivePayload, isOrderCreatedEvent),
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

    const changedFields = changedOrderFields(
      existing,
      effectivePayload,
      update,
    );
    await this.audit.logOrderEvent({
      orgId,
      haravanOrderId: payload.id,
      action: existing ? OrderEventAction.UPDATED : OrderEventAction.CREATED,
      source,
      topic,
      changedFields,
      description: existing
        ? changedFields.length
          ? `Cập nhật đơn hàng từ ${
              source === 'webhook' ? `webhook ${topic ?? ''}` : source
            }.`
          : `Nhận ${
              source === 'webhook' ? `webhook ${topic ?? ''}` : source
            }; không có trường đơn hàng thay đổi.`
        : `Tạo đơn hàng từ ${
            source === 'webhook' ? `webhook ${topic ?? ''}` : source
          }.`,
    });

    this.logger.log(
      `Luu don ${orderNumber} (org ${orgId}, source ${source}): ` +
        `${payload.financial_status ?? 'n/a'} / ${
          doc.confirmedStatus ?? 'unconfirmed'
        }`,
    );

    return { created: true, order: doc };
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

    const phone = normalizePhone(
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

    try {
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
    } catch (error) {
      if ((error as { code?: number })?.code !== 11000) throw error;

      // Duplicate webhooks can race after both workers pass the initial lookup.
      const racedCustomer = await this.customerModel
        .findOne({ orgId, $or: or })
        .lean()
        .exec();
      if (racedCustomer) {
        await this.customerModel
          .updateOne(
            { _id: racedCustomer._id },
            { $set: patch, $addToSet: { orderIds: payload.id } },
          )
          .exec();
      } else {
        this.logger.warn(
          `Bo qua dong bo khach don ${payload.id} do xung dot khoa duy nhat`,
        );
      }
      return;
    }

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
    const identity = {
      haravanId: cust?.haravanId,
      email: cust?.email ?? order.email,
      phone: cust?.phone ?? order.phone,
      fullName: cust?.fullName ?? order.customerName,
    };
    if (!hasRealCustomerIdentity(identity)) {
      return { priorOrderCount: 0, priorSpent: 0 };
    }

    const phone =
      normalizePhone(cust?.phone) ??
      normalizePhone(order.phone);
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
    const hasCustomerIdentity = hasRealCustomerIdentity({
      haravanId: order.customer?.haravanId,
      email: order.customer?.email ?? order.email,
      phone: order.customer?.phone ?? order.phone,
      fullName: order.customer?.fullName ?? order.customerName,
    });

    const { priorOrderCount, priorSpent } = await this.countPriorOrders(
      orgId,
      order,
    );

    return decideConfirm({
      hasCustomerIdentity,
      isCancelledOrClosed:
        order.cancelledStatus === 'cancelled' ||
        order.closedStatus === 'closed',
      isAlreadyConfirmed:
        order.payload?.confirmed_status?.toLowerCase() === 'confirmed',
      priorOrderCount,
      priorSpent,
      rule: this.rule,
    });
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

    await this.audit.logAction(
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

      if (manual) {
        await this.audit.logOrderEvent({
          orgId,
          haravanOrderId,
          action: OrderEventAction.CONFIRM_FAILED,
          source: 'user',
          actor,
          changedFields: ['status', 'processing.reason'],
          description: `Thao tác xác nhận bị bỏ qua: ${decision.skipReason}.`,
        });
      }

      await this.audit.logAction(
        orgId,
        haravanOrderId,
        ActionType.CONFIRM_FAILED,
        ActionResult.SKIPPED,
        { reason: decision.skipReason, manual, actor },
      );

      return { order, confirmed: false, decision };
    }

    await this.audit.logAction(
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

      // Haravan tra ve payload don hang da xac nhan; dong bo ngay de FE reload
      // la thay trang thai moi, khong phai cho webhook orders/update.
      let mirrored: OrderDocument | null = null;
      try {
        mirrored = await this.mirrorOrderFromApi(
          orgId,
          haravanOrderId,
          res.body,
        );
      } catch (mirrorError) {
        // Haravan da xac nhan xong; chi can giu duong fallback de khong
        // bao loi xac nhan khi dong bo that bai.
        this.logger.warn(
          `Khong dong bo duoc don ${haravanOrderId} sau khi xac nhan: ` +
            `${(mirrorError as Error).message}`,
        );
      }
      const target = mirrored ?? order;
      target.status = OrderStatus.CONFIRMED;
      target.processing = { ...target.processing, ...toProcessing(decision) };
      if (target.confirmedStatus?.toLowerCase() !== 'confirmed') {
        target.confirmedStatus = 'confirmed';
      }
      if (target.payload?.confirmed_status?.toLowerCase() !== 'confirmed') {
        target.payload = {
          ...(target.payload ?? {}),
          confirmed_status: 'confirmed',
        } as OrderPayload;
      }
      await target.save();

      if (manual) {
        await this.audit.logOrderEvent({
          orgId,
          haravanOrderId,
          action: OrderEventAction.CONFIRM_REQUESTED,
          source: 'user',
          actor,
          changedFields: ['status', 'processing'],
          description:
            'Đã gửi yêu cầu xác nhận; trạng thái sẽ cập nhật theo payload webhook Haravan.',
        });
      }

      const actionLogId = await this.audit.logAction(
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

      this.logger.log(
        `Da gui yeu cau xac nhan don ${haravanOrderId} (org ${orgId})`,
      );

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

      if (manual) {
        await this.audit.logOrderEvent({
          orgId,
          haravanOrderId,
          action: OrderEventAction.CONFIRM_FAILED,
          source: 'user',
          actor,
          changedFields: ['status', 'processing.reason', 'processing.error'],
          description: 'Người dùng xác nhận đơn hàng nhưng thao tác thất bại.',
        });
      }

      await this.audit.logAction(
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

  /**
   * Đồng bộ lại bản ghi đơn khi response của Haravan có trả payload đơn.
   * Trả về null khi response không chứa payload (khi đó caller tự cập nhật doc).
   */
  async mirrorOrderFromApi(
    orgId: number,
    haravanOrderId: number,
    body: unknown,
  ): Promise<OrderDocument | null> {
    if (!body || typeof body !== 'object') return null;

    const wrapper = body as { order?: unknown };
    const candidate = (wrapper.order ?? body) as OrderPayload;
    if (!candidate || !Number.isFinite(Number(candidate.id))) return null;

    const result = await this.upsertOrder(orgId, candidate, 'api');
    return result.order;
  }

  async findOrderById(
    orgId: number,
    haravanOrderId: number,
  ): Promise<OrderDocument | null> {
    return this.orderModel.findOne({ orgId, haravanOrderId }).exec();
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
