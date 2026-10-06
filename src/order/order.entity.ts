import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';
import {
  FINANCIAL_STATUSES,
  FinancialStatus,
  FULFILLMENT_STATUSES,
  FulfillmentStatus,
  OrderPayload,
} from '../interface/order.interface';

/** Ly do khong auto-confirm */
export enum SkipReason {
  NONE = 'none',
  NO_CUSTOMER = 'no_customer',
  FIRST_TIME_BUYER = 'first_time_buyer',
  NOT_ENOUGH_PRIOR_ORDERS = 'not_enough_prior_orders',
  NOT_ENOUGH_PRIOR_SPENT = 'not_enough_prior_spent',
  ALREADY_CONFIRMED = 'already_confirmed',
  INVALID_PAYMENT = 'invalid_payment',
  ORDER_CANCELLED = 'order_cancelled',
  CONFIRM_ERROR = 'confirm_error',
}

/** Trang thai noi bo cua BE, tach khoi confirmedStatus cua Harovan */
export enum OrderStatus {
  PENDING = 'pending',
  PROCESSING = 'processing',
  CONFIRMED = 'confirmed',
  FAILED = 'failed',
  SKIPPED = 'skipped',
  CANCELLED = 'cancelled',
}

@Schema({ _id: false })
export class CustomerSnapshot {
  @Prop() haravanId?: number;
  @Prop() email?: string;
  @Prop() phone?: string;
  @Prop() firstName?: string;
  @Prop() lastName?: string;
  /**
   * Haravan snapshot; prior-order eligibility is counted from stored BE orders.
   */
  @Prop() ordersCount?: number;
  @Prop() totalSpent?: number;
  @Prop() totalPaid?: number;
  @Prop() state?: string;
  @Prop() verifiedEmail?: boolean;
  @Prop() lastOrderId?: number;
  @Prop() lastOrderName?: string;
  @Prop() fullName?: string;
}
export const CustomerSnapshotSchema =
  SchemaFactory.createForClass(CustomerSnapshot);

@Schema({ _id: false })
export class OrderProcessing {
  @Prop({ required: true, enum: SkipReason, default: SkipReason.NONE })
  reason!: SkipReason;

  @Prop({ default: false })
  isReturningCustomer!: boolean;

  /** So don khach da mua TRUOC don nay */
  @Prop({ default: 0 })
  priorOrderCount!: number;

  @Prop({ default: 0 })
  priorSpent!: number;

  @Prop() source?: 'webhook' | 'api' | 'manual';
  @Prop() jobId?: string;
  @Prop() error?: string;
}
export const OrderProcessingSchema =
  SchemaFactory.createForClass(OrderProcessing);

@Schema({ collection: 'orders', timestamps: true })
export class Order {
  @Prop({ required: true, index: true })
  orgId!: number;

  @Prop({ required: true, index: true })
  haravanOrderId!: number;

  @Prop({ index: true })
  orderNumber?: string;

  @Prop({ index: true })
  orderName?: string;

  @Prop() email?: string;
  @Prop() phone?: string;

  /** Ten khach lay tu shipping_address.name, de log/doc nhanh */
  @Prop() customerName?: string;

  @Prop({ type: String, enum: FINANCIAL_STATUSES })
  financialStatus?: FinancialStatus;

  @Prop({ type: String, enum: [...FULFILLMENT_STATUSES, null], default: null })
  fulfillmentStatus?: FulfillmentStatus;

  /** Trang thai xac nhan phia Harovan: confirmed / unconfirmed */
  @Prop() confirmedStatus?: string;

  @Prop() cancelledStatus?: string;
  @Prop() closedStatus?: string;
  @Prop() cancelReason?: string;
  @Prop() gateway?: string;
  @Prop() sourceName?: string;

  @Prop({ default: 0 })
  totalPrice?: number;
  @Prop({ default: 0 })
  subtotalPrice?: number;
  @Prop({ default: 0 })
  totalTax?: number;
  @Prop({ default: 0 })
  totalDiscounts?: number;
  @Prop({ default: 'VND' })
  currency?: string;

  @Prop({ type: CustomerSnapshotSchema })
  customer?: CustomerSnapshot;

  @Prop({ default: 0 })
  itemCount?: number;

  @Prop({ type: [Object], default: [] })
  lineItems?: Record<string, unknown>[];

  @Prop({ type: Object })
  shippingAddress?: Record<string, unknown>;
  @Prop({ type: Object })
  billingAddress?: Record<string, unknown>;

  @Prop({
    type: String,
    enum: OrderStatus,
    default: OrderStatus.PENDING,
    index: true,
  })
  status!: OrderStatus;

  @Prop({ type: OrderProcessingSchema, default: () => ({}) })
  processing!: OrderProcessing;

  @Prop({ type: Object })
  payload?: OrderPayload;

  @Prop() lastWebhookAt?: Date;
  @Prop() lastWebhookTopic?: string;
}
export type OrderDocument = HydratedDocument<Order>;

export const OrderSchema = SchemaFactory.createForClass(Order);

/** Idempotent: mot don chi ton tai mot lan theo (orgId, haravanOrderId) */
OrderSchema.index({ orgId: 1, haravanOrderId: 1 }, { unique: true });
OrderSchema.index({ createdAt: -1 });
OrderSchema.index({ status: 1, createdAt: -1 });
OrderSchema.index({ orgId: 1, phone: 1 });
OrderSchema.index({ orgId: 1, 'customer.haravanId': 1 });

/* ------------------------------------------------------------ order action */

export enum ActionType {
  EVALUATE = 'evaluate',
  PROCESS = 'process',
  CONFIRM_SEND = 'confirm_send',
  CONFIRM_SUCCESS = 'confirm_success',
  CONFIRM_FAILED = 'confirm_failed',
  REPLAY = 'replay',
}

export enum ActionResult {
  SUCCESS = 'success',
  FAILED = 'failed',
  SKIPPED = 'skipped',
}

/** Chi tiet request/response khi goi Omni API (khong luu access token) */
@Schema({ _id: false })
export class ApiCall {
  @Prop() method?: string;
  @Prop() url?: string;
  @Prop({ type: Object }) requestBody?: Record<string, unknown>;
  @Prop() statusCode?: number;
  @Prop({ type: Object }) responseBody?: Record<string, unknown>;
  @Prop() durationMs?: number;
}
export const ApiCallSchema = SchemaFactory.createForClass(ApiCall);

@Schema({ collection: 'order_actions', timestamps: true })
export class OrderAction {
  @Prop({ required: true, index: true })
  orgId!: number;

  @Prop({ required: true, index: true })
  haravanOrderId!: number;

  @Prop({ required: true, enum: ActionType })
  type!: ActionType;

  @Prop({ required: true, enum: ActionResult })
  result!: ActionResult;

  @Prop({ default: false })
  manual!: boolean;

  @Prop() actor?: string;
  @Prop({ type: String, enum: SkipReason })
  reason?: SkipReason;
  @Prop() message?: string;

  @Prop({ default: 1 })
  attempt?: number;

  @Prop({ type: ApiCallSchema })
  apiCall?: ApiCall;
}
export type OrderActionDocument = HydratedDocument<OrderAction>;

export const OrderActionSchema = SchemaFactory.createForClass(OrderAction);

OrderActionSchema.index({ orgId: 1, haravanOrderId: 1, createdAt: -1 });
