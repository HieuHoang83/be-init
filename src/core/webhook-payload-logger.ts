import { appendFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Ghi thông tin webhook vào tệp để tiện kiểm tra.
 */
const LOG_DIR = join(process.cwd(), 'logs');
const LOG_FILE = join(LOG_DIR, 'webhook.log');
const MAX_RAW = 20_000;

/** Tên hiển thị ngắn gọn trong log. */
const KIND_LABEL: Record<string, string> = {
  private: 'Webhook rieng tu (Haravan admin)',
  app: 'Webhook ket noi App (co subscribe)',
  subscribe: 'Dang ky webhook (goi Haravan)',
};

export interface WebhookLogInput {
  /** 'app' | 'private' | 'subscribe' */
  kind: keyof typeof KIND_LABEL | string;
  /**
   * Loại luồng để phân biệt các bước trong log:
   *  - `verify_token`: GET đăng ký ứng dụng bằng hub.verify_token và hub.challenge.
   *  - `event_notification`: POST webhook đơn hàng có chữ ký HMAC.
   *  - `hmac_rejected`: POST bị từ chối do chữ ký không hợp lệ.
   *  - `oauth_callback`: GET trả về từ bước OAuth.
   */
  flow?:
    | 'verify_token'
    | 'event_notification'
    | 'hmac_rejected'
    | 'oauth_callback'
    | string;
  /** `received`: guard đã nhận yêu cầu; `processed`: controller đã xử lý xong. */
  stage?: 'received' | 'processed';
  method?: string | null;
  path?: string | null;
  topic?: string | null;
  orgId?: number | null;
  haravanOrderId?: number | null;
  status?: number;
  raw?: string | null;
  body?: unknown;
  headers?: Record<string, string>;
  result?: Record<string, unknown>;
  error?: string;
}

export function logWebhookPayload(data: WebhookLogInput): void {
  const entry = {
    at: new Date().toISOString(),
    endpoint: `${data.method ?? '?'} ${data.path ?? '?'}`,
    kind: data.kind,
    kindLabel: KIND_LABEL[data.kind] ?? data.kind,
    stage: data.stage ?? 'received',
    ...data,
    raw:
      typeof data.raw === 'string' && data.raw.length > MAX_RAW
        ? data.raw.slice(0, MAX_RAW) +
          `...[+${data.raw.length - MAX_RAW} bytes]`
        : data.raw,
  };

  mkdirSync(LOG_DIR, { recursive: true });
  appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n', 'utf8');
}
