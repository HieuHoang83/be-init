import { OrderPayload } from '../../interface/order.interface';
import { ConfirmDecision } from '../rules/order.rules';

/** Gộp hai object, bỏ qua các giá trị null/undefined của object mới. */
export function mergeNonNull<T extends object>(
  existing?: T | null,
  incoming?: T | null,
): T | undefined {
  if (!existing && !incoming) return undefined;
  const merged: Record<string, unknown> = { ...(existing ?? {}) };
  for (const [key, value] of Object.entries(incoming ?? {})) {
    if (value !== undefined && value !== null) merged[key] = value;
  }
  return merged as T;
}

/**
 * Gộp payload mới vào payload đã lưu.
 * `preserveNulls = true` khi đọc lại từ API: Haravan có thể trả null cho field
 * mà payload webhook trước đó đã có giá trị — khi đó giữ giá trị cũ.
 */
export function mergeOrderPayload(
  existing: OrderPayload | undefined,
  incoming: OrderPayload,
  preserveNulls = false,
): OrderPayload {
  const customer = mergeNonNull(existing?.customer, incoming.customer);
  const shipping = mergeNonNull(
    existing?.shipping_address,
    incoming.shipping_address,
  );
  const billing = mergeNonNull(
    existing?.billing_address,
    incoming.billing_address,
  );

  return {
    ...(preserveNulls
      ? mergeNonNull(existing, incoming)
      : { ...existing, ...incoming }),
    ...(customer ? { customer } : {}),
    ...(shipping ? { shipping_address: shipping } : {}),
    ...(billing ? { billing_address: billing } : {}),
  };
}

/** Chuẩn hoá số điện thoại để so khớp khách hàng. */
export function normalizePhone(raw?: string | null): string | undefined {
  if (!raw) return undefined;
  const digits = String(raw).replace(/\D/g, '');
  if (!digits) return undefined;
  const local = digits.replace(/^84/, '0').replace(/^0+/, '0');
  return local.length >= 9 && local.length <= 15 ? local : undefined;
}

/** Tên hiển thị của khách, ưu tiên tên trong địa chỉ giao hàng. */
export function resolveFullName(payload: OrderPayload): string | undefined {
  return (
    (payload.shipping_address?.name ?? '').trim() ||
    [payload.customer?.first_name, payload.customer?.last_name]
      .filter(Boolean)
      .join(' ')
      .trim() ||
    undefined
  );
}

/** Chỉ cập nhật các trường khách hàng có dữ liệu. */
export function buildCustomerPatch(
  payload: OrderPayload,
  includeCreationSnapshot: boolean,
): Record<string, unknown> {
  const c = payload.customer;
  if (!c) return {};

  const fullName = resolveFullName(payload);
  const patch: Record<string, unknown> = {};
  const setWhenPresent = (field: string, value: unknown) => {
    if (value !== undefined && value !== null) {
      patch[`customer.${field}`] = value;
    }
  };

  setWhenPresent('email', c.email?.toLowerCase());
  setWhenPresent(
    'phone',
    normalizePhone(c.phone ?? payload.shipping_address?.phone),
  );
  setWhenPresent('totalSpent', c.total_spent);
  setWhenPresent('totalPaid', c.total_paid);
  setWhenPresent('state', c.state);
  setWhenPresent('verifiedEmail', c.verified_email);
  setWhenPresent('lastOrderId', c.last_order_id);
  setWhenPresent('lastOrderName', c.last_order_name);
  if (includeCreationSnapshot && c.orders_count != null) {
    patch['customer.ordersCount'] = c.orders_count;
  }

  if (c.first_name) patch['customer.firstName'] = c.first_name;
  if (c.last_name) patch['customer.lastName'] = c.last_name;
  if (fullName) patch['customer.fullName'] = fullName;
  if (c.id) patch['customer.haravanId'] = c.id;

  const orderPhone = normalizePhone(
    c.phone ?? payload.shipping_address?.phone,
  );
  if (orderPhone) patch['phone'] = orderPhone;
  if (c.email) patch['email'] = c.email.toLowerCase();
  if (fullName) patch['customerName'] = fullName;

  return patch;
}

/** Suy ra vòng đời đơn (open/closed/cancelled) từ payload Haravan. */
export function resolveHaravanOrderStatus(
  payload: OrderPayload,
): 'open' | 'closed' | 'cancelled' | null {
  const status = payload.status?.toLowerCase();
  if (status === 'open' || status === 'closed' || status === 'cancelled') {
    return status;
  }
  const cancelledStatus = payload.cancelled_status?.toLowerCase();
  if (
    cancelledStatus === 'cancelled' ||
    cancelledStatus === 'true' ||
    payload.cancelled_at
  ) {
    return 'cancelled';
  }
  const closedStatus = payload.closed_status?.toLowerCase();
  if (
    closedStatus === 'closed' ||
    closedStatus === 'true' ||
    payload.closed_at
  ) {
    return 'closed';
  }
  if (cancelledStatus === 'uncancelled' && closedStatus === 'unclosed') {
    return 'open';
  }
  return null;
}

/** Các trường đơn thực sự thay đổi so với bản ghi trước đó. */
export function changedOrderFields(
  existing: Record<string, unknown> | null,
  payload: OrderPayload,
  update: Record<string, unknown>,
): string[] {
  const previousPayload = (existing?.['payload'] ?? {}) as Record<
    string,
    unknown
  >;
  const fields: Array<{
    label: string;
    current: unknown;
    previous: unknown;
  }> = [
    {
      label: 'status',
      current: update['status'],
      previous: existing?.['status'],
    },
    {
      label: 'orderName',
      current: update['orderName'],
      previous: existing?.['orderName'],
    },
    {
      label: 'orderNumber',
      current: update['orderNumber'],
      previous: existing?.['orderNumber'],
    },
    {
      label: 'customerName',
      current: update['customerName'],
      previous: existing?.['customerName'],
    },
    {
      label: 'email',
      current: update['email'],
      previous: existing?.['email'],
    },
    {
      label: 'phone',
      current: update['phone'],
      previous: existing?.['phone'],
    },
    {
      label: 'financialStatus',
      current: update['financialStatus'],
      previous: existing?.['financialStatus'],
    },
    {
      label: 'fulfillmentStatus',
      current: update['fulfillmentStatus'],
      previous: existing?.['fulfillmentStatus'],
    },
    {
      label: 'confirmedStatus',
      current: update['confirmedStatus'],
      previous: existing?.['confirmedStatus'],
    },
    {
      label: 'haravanStatus',
      current: update['haravanStatus'],
      previous: existing?.['haravanStatus'],
    },
    {
      label: 'gateway',
      current: update['gateway'],
      previous: existing?.['gateway'],
    },
    {
      label: 'sourceName',
      current: update['sourceName'],
      previous: existing?.['sourceName'],
    },
    {
      label: 'totalPrice',
      current: update['totalPrice'],
      previous: existing?.['totalPrice'],
    },
    {
      label: 'subtotalPrice',
      current: update['subtotalPrice'],
      previous: existing?.['subtotalPrice'],
    },
    {
      label: 'totalTax',
      current: update['totalTax'],
      previous: existing?.['totalTax'],
    },
    {
      label: 'totalDiscounts',
      current: update['totalDiscounts'],
      previous: existing?.['totalDiscounts'],
    },
    {
      label: 'itemCount',
      current: update['itemCount'],
      previous: existing?.['itemCount'],
    },
    {
      label: 'lineItems',
      current: update['lineItems'],
      previous: existing?.['lineItems'],
    },
    {
      label: 'shippingAddress',
      current: update['shippingAddress'],
      previous: existing?.['shippingAddress'],
    },
    {
      label: 'billingAddress',
      current: update['billingAddress'],
      previous: existing?.['billingAddress'],
    },
    {
      label: 'note',
      current: payload.note,
      previous: previousPayload['note'],
    },
    {
      label: 'discount_codes',
      current: payload.discount_codes,
      previous: previousPayload['discount_codes'],
    },
    {
      label: 'discount_applications',
      current: payload.discount_applications,
      previous: previousPayload['discount_applications'],
    },
    {
      label: 'note_attributes',
      current: payload.note_attributes,
      previous: previousPayload['note_attributes'],
    },
  ];

  return fields
    .filter(({ current, previous }) => {
      if (current === undefined) return false;
      return (
        !existing ||
        JSON.stringify(current ?? null) !== JSON.stringify(previous ?? null)
      );
    })
    .map(({ label }) => label);
}

/** Rút gọn quyết định xác nhận xuống phần lưu vào `order.processing`. */
export function toProcessing(decision: ConfirmDecision) {
  return {
    reason: decision.skipReason,
    isReturningCustomer: decision.isReturningCustomer,
    priorOrderCount: decision.priorOrderCount,
    priorSpent: decision.priorSpent,
  };
}
