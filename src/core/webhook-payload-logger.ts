import { appendFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Ghi log payload webhook ra file de debug.
 * Console cua app chay o terminal khac, file thi doc duoc tu moi noi.
 */
const LOG_DIR = join(process.cwd(), 'logs');
const LOG_FILE = join(LOG_DIR, 'webhook.log');
const MAX_RAW = 20_000;

/** Ten gon de doc nhanh trong log */
const KIND_LABEL: Record<string, string> = {
  private: 'Webhook rieng tu (Haravan admin)',
  app: 'Webhook ket noi App (co subscribe)',
  subscribe: 'Dang ky webhook (goi Haravan)',
};

export interface WebhookLogInput {
  /** 'app' | 'private' | 'subscribe' */
  kind: keyof typeof KIND_LABEL | string;
  /**
   * Loai luong, de phan biet ngay trong log:
   *  - `verify_token`      GET  ?hub.mode=subscribe&hub.verify_token&hub.challenge
   *                        Dung HARAVAN_APP_VERIFY_TOKEN, chi mot lan luc cai app.
   *  - `event_notification` POST co X-Haravan-Hmacsha256 + X-Haravan-Topic
   *                        Event that tu Haravan moi don, KHONG co verify token.
   *  - `hmac_rejected`     POST bi tu choi vi chu ky sai -> status 401
   *  - `oauth_callback`    GET /webhooks/callback?code=...
   */
  flow?:
    | 'verify_token'
    | 'event_notification'
    | 'hmac_rejected'
    | 'oauth_callback'
    | string;
  /** `received` = guard xac nhan da nhan; `processed` = controller xu ly xong */
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
        ? data.raw.slice(0, MAX_RAW) + `...[+${data.raw.length - MAX_RAW} bytes]`
        : data.raw,
  };

  mkdirSync(LOG_DIR, { recursive: true });
  appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n', 'utf8');
}
