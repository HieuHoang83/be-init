import { OrderPayload, WebhookEnvelope } from '../interface/order.interface';

/**
 * Harovan gui metadata qua HEADER, khong nam trong body:
 *
 *   X-Haravan-Topic:    orders/create
 *   X-Haravan-Org-Id:   200001220496
 *   X-Haravan-Order-Id: 176832
 *   X-Haravan-Hmacsha256: <chu ky>
 *   X-Haravan-Test:     True          (payload test, khong phai don that)
 *
 * Body la RESOURCE TRUC TIEP (order object), khong boc trong `{ org_id, topic, data }`.
 * Van giu fallback doc body phong khi doi chieu / test gia lap.
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
 * Doc metadata tu header truoc, fallback body.
 * `headers` phai la header da lowercase (Express da chuan hoa).
 */
export function readWebhookMeta(
  headers: Record<string, unknown> | undefined,
  body?: unknown,
): WebhookMeta {
  const h = headers ?? {};
  const b = (body ?? {}) as Record<string, unknown>;

  const topic =
    (typeof h['x-haravan-topic'] === 'string' ? h['x-haravan-topic'] : undefined) ??
    (typeof b.topic === 'string' ? b.topic : undefined) ??
    'unknown';

  const orgId =
    toInt(h['x-haravan-org-id']) ?? toInt(b.org_id) ?? null;

  const orderId = toInt(h['x-haravan-order-id']) ?? toInt((b as OrderPayload).id) ?? null;

  const isTest =
    h['x-haravan-test'] === 'true' ||
    h['x-haravan-test'] === 'True' ||
    b.send_webhooks === false;

  return { topic, orgId, orderId, isTest };
}

/** Header chua org_id, dung khi resolve secret phai tra 200 nhanh. */
export function extractOrgId(
  headers: Record<string, unknown> | undefined,
  body?: unknown,
): number | null {
  return readWebhookMeta(headers, body).orgId;
}

/** Topic tu header, fallback body, luon tra chuoi. */
export function extractTopic(
  headers: Record<string, unknown> | undefined,
  body?: unknown,
): string {
  return readWebhookMeta(headers, body).topic;
}

/**
 * Lay order ra tu body.
 *
 * 3 dang Haravan co the gui:
 *   1. order truc tiep:                 { id, name, customer, ... }
 *   2. boc trong data:                 { data: { id, ... } }
 *   3. boc trong data.order:           { data: { order: { id } } }
 *
 * Order lay tu `X-Haravan-Order-Id` khi body khong co `id` (payload test).
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

  // dang 3: { data: { order: {...} } }
  if (raw.data && typeof raw.data === 'object') {
    const data = raw.data as Record<string, unknown>;
    order = (data.order ?? data) as OrderPayload;
  }

  // Payload test co the body rong -> dung orderId tu header de tao skeleton
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
