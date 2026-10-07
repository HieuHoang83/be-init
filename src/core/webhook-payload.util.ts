import { OrderPayload, WebhookEnvelope } from '../interface/order.interface';

/**
 * Haravan gửi thông tin webhook qua header, không đặt trong body:
 *
 *   X-Haravan-Topic:    orders/create
 *   X-Haravan-Org-Id:   200001220496
 *   X-Haravan-Order-Id: 176832
 *   X-Haravan-Hmacsha256: <chu ky>
 *   X-Haravan-Test:     True          (payload kiểm tra, không phải đơn thật)
 *
 * Body thường là đối tượng đơn hàng trực tiếp, không bọc trong
 * `{ org_id, topic, data }`. Vẫn hỗ trợ đọc metadata từ body để đối chiếu
 * hoặc kiểm thử.
 */

export interface WebhookMeta {
  topic: string;
  orgId: number | null;
  orderId: number | null;
  isTest: boolean;
}

function toInt(value: unknown): number | null {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : null;
}

/**
 * Đọc thông tin từ header trước, sau đó mới dùng body nếu thiếu.
 * Tên header được Express chuyển thành chữ thường.
 */
export function readWebhookMeta(
  headers: Record<string, unknown> | undefined,
  body?: unknown,
): WebhookMeta {
  const h = headers ?? {};
  const b = (body ?? {}) as Record<string, unknown>;

  const topic =
    (typeof h['x-haravan-topic'] === 'string'
      ? h['x-haravan-topic']
      : undefined) ??
    (typeof b.topic === 'string' ? b.topic : undefined) ??
    'unknown';

  const orgId = toInt(h['x-haravan-org-id']) ?? toInt(b.org_id) ?? null;

  const orderId =
    toInt(h['x-haravan-order-id']) ?? toInt((b as OrderPayload).id) ?? null;

  const isTest =
    h['x-haravan-test'] === 'true' ||
    h['x-haravan-test'] === 'True' ||
    b.send_webhooks === false;

  return { topic, orgId, orderId, isTest };
}

/** Đọc org_id từ header hoặc body để tìm secret xác thực. */
export function extractOrgId(
  headers: Record<string, unknown> | undefined,
  body?: unknown,
): number | null {
  return readWebhookMeta(headers, body).orgId;
}

/** Đọc chủ đề từ header hoặc body; luôn trả về chuỗi. */
export function extractTopic(
  headers: Record<string, unknown> | undefined,
  body?: unknown,
): string {
  return readWebhookMeta(headers, body).topic;
}

/**
 * Lấy đơn hàng từ body.
 *
 * Haravan có thể gửi theo ba dạng:
 *   1. Đơn hàng trực tiếp:              { id, name, customer, ... }
 *   2. Bọc trong data:                  { data: { id, ... } }
 *   3. Bọc trong data.order:            { data: { order: { id } } }
 *
 * Nếu body không có `id`, lấy mã đơn từ `X-Haravan-Order-Id`.
 */
export function extractOrder(
  headers: Record<string, unknown> | undefined,
  body: unknown,
): { orgId: number; order: OrderPayload } {
  const meta = readWebhookMeta(headers, body);

  if (!meta.orgId) {
    throw new Error(
      'Webhook thieu org_id: khong co trong header X-Haravan-Org-Id hay body.org_id',
    );
  }

  const raw = body as Record<string, unknown>;

  let order = raw as OrderPayload;

  // Dạng 3: { data: { order: {...} } }.
  if (raw.data && typeof raw.data === 'object') {
    const data = raw.data as Record<string, unknown>;
    order = (data.order ?? data) as OrderPayload;
  }

  // Payload kiểm tra có thể rỗng; dùng mã đơn trong header để tạo dữ liệu khung.
  if (!order.id && meta.orderId) {
    order = { ...order, id: meta.orderId };
  }

  if (!order.id) {
    throw new Error(
      'Webhook thieu don hang: khong co body.id, data.id hay X-Haravan-Order-Id',
    );
  }

  return { orgId: meta.orgId, order };
}

export type { WebhookEnvelope };
