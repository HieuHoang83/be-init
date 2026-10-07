/**
 * Kiểu dữ liệu payload từ Omni API + webhook.
 * Nguồn: https://docs.haravan.com/docs/omni-apis/orders/
 *        https://docs.haravan.com/docs/tutorials/webhooks/connect-webhook/
 *
 * Haravan trả về rất nhiều field và phần lớn nullable, có thể bổ sung thêm.
 * Vì vậy payload gốc luôn được lưu nguyên bản (raw) vào MongoDB.
 */

export interface Address {
  address1?: string | null;
  address2?: string | null;
  city?: string | null;
  company?: string | null;
  country?: string | null;
  country_code?: string | null;
  first_name?: string | null;
  last_name?: string | null;
  name?: string | null;
  phone?: string | null;
  province?: string | null;
  province_code?: string | null;
  zip?: string | null;
  district?: string | null;
  district_code?: string | null;
  ward?: string | null;
  ward_code?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  id?: number | null;
  default?: boolean | null;
}

export interface CustomerPayload {
  id?: number;
  email?: string | null;
  phone?: string | null;
  first_name?: string | null;
  last_name?: string | null;
  /** Số đơn Haravan ghi nhận tại thời điểm nhận dữ liệu, gồm đơn hiện tại nếu có. */
  orders_count?: number | null;
  total_spent?: number | null;
  total_paid?: number | null;
  state?: string | null;
  verified_email?: boolean | null;
  accepts_marketing?: boolean | null;
  group_name?: string | null;
  last_order_id?: number | null;
  last_order_name?: string | null;
  default_address?: Address | null;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface LineItemPayload {
  id?: number;
  product_id?: number | null;
  variant_id?: number | null;
  title?: string | null;
  variant_title?: string | null;
  name?: string | null;
  sku?: string | null;
  barcode?: string | null;
  vendor?: string | null;
  quantity?: number | null;
  price?: number | null;
  price_original?: number | null;
  price_promotion?: number | null;
  total_discount?: number | null;
  grams?: number | null;
  gift_card?: boolean | null;
  taxable?: boolean | null;
  requires_shipping?: boolean | null;
  fulfillment_status?: string | null;
  properties?: unknown;
  [key: string]: unknown;
}

export const FINANCIAL_STATUSES = [
  'pending',
  'authorized',
  'partially_paid',
  'paid',
  'partially_refunded',
  'refunded',
  'voided',
] as const;

export type FinancialStatus = typeof FINANCIAL_STATUSES[number];

export const HARAVAN_FINANCIAL_FILTERS = [
  'pending',
  'paid',
  'partially_paid',
  'refunded',
  'voided',
  'partially_refunded',
] as const;

export const FULFILLMENT_STATUSES = [
  'fulfilled',
  'notfulfilled',
  'partial',
  'restocked',
] as const;

export type FulfillmentStatus = typeof FULFILLMENT_STATUSES[number] | null;

export const HARAVAN_FULFILLMENT_FILTERS = [
  'unshipped',
  'shipped',
  'partial',
] as const;

export type HaravanFulfillmentFilter =
  typeof HARAVAN_FULFILLMENT_FILTERS[number];

export const HARAVAN_ORDER_STATUSES = ['open', 'closed', 'cancelled'] as const;

export type HaravanOrderStatus = typeof HARAVAN_ORDER_STATUSES[number];

export interface OrderPayload {
  id: number;
  status?: HaravanOrderStatus | null;
  name?: string | null;
  order_number?: string | null;
  number?: number | null;
  email?: string | null;
  contact_email?: string | null;
  currency?: string | null;
  gateway?: string | null;
  gateway_code?: string | null;
  financial_status?: FinancialStatus | null;
  fulfillment_status?: FulfillmentStatus;
  confirmed_status?: string | null;
  cancelled_status?: string | null;
  closed_status?: string | null;
  cancel_reason?: string | null;
  source_name?: string | null;
  note?: string | null;
  tags?: string | null;
  subtotal_price?: number | null;
  total_price?: number | null;
  total_line_items_price?: number | null;
  total_discounts?: number | null;
  total_tax?: number | null;
  total_weight?: number | null;
  customer?: CustomerPayload | null;
  line_items?: LineItemPayload[] | null;
  shipping_address?: Address | null;
  billing_address?: Address | null;
  shipping_lines?: unknown[] | null;
  discount_codes?: unknown[] | null;
  note_attributes?: unknown[] | null;
  confirmed_at?: string | null;
  cancelled_at?: string | null;
  closed_at?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  [key: string]: unknown;
}

/** Cấu trúc webhook: { org_id, topic, data: <order> }. */
export interface WebhookEnvelope {
  org_id?: number | string | null;
  topic?: string | null;
  created_at?: string | null;
  /** Với orders/create, data là đơn hàng trực tiếp hoặc object { order }. */
  data?: OrderPayload | { order?: OrderPayload } | null;
  [key: string]: unknown;
}

export const TOPICS = {
  ORDER_CREATE: 'orders/create',
  ORDER_UPDATE: 'orders/update',
  ORDER_CANCEL: 'orders/cancel',
  ORDER_PAID: 'orders/paid',
  CUSTOMER_CREATE: 'customers/create',
  CUSTOMER_UPDATE: 'customers/update',
  APP_UNINSTALLED: 'app/uninstalled',
  SHOP_UPDATE: 'shop/update',
} as const;

export type Topic = typeof TOPICS[keyof typeof TOPICS];

export interface ChallengeQuery {
  'hub.mode'?: string;
  'hub.verify_token'?: string;
  'hub.challenge'?: string;
  [key: string]: unknown;
}
