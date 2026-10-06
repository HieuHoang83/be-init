import { registerAs } from '@nestjs/config';

export interface RuleConfig {
  /** Số đơn khách đã mua TRƯỚC đơn này tối thiểu để auto confirm. */
  minPriorOrders: number;
  /** Tổng chi tiêu tối thiểu trước đơn này (VND). 0 = bỏ qua. */
  minPriorSpent: number;
}

export interface ApiConfig {
  baseUrl: string;
  /** API subscribe webhook: webhook.haravan.com (khac host Omni API) */
  webhookBaseUrl: string;
  timeoutMs: number;
  maxRetries: number;
  retryBaseDelayMs: number;
  /** OAuth: doi authorization code lay access token (buoc 3 cua Haravan App) */
  oauth: OAuthConfig;
}

export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  /** Phai GION CHINH XAC redirect_uri dung o buoc authorize */
  redirectUri: string;
}

export interface QueueConfig {
  concurrency: number;
  maxAttempts: number;
  backoffBaseMs: number;
  backoffMaxMs: number;
  /** Bao lau poll co job moi */
  pollIntervalMs: number;
  /** Bao lau worker nap lai heartbeat (nhip tim) */
  heartbeatIntervalMs: number;
  /** Worker giu job toi da lau thi job xem nhu worker da chet */
  leaseMs: number;
  /** Bao lau quet cac job running qua han heartbeat */
  reclaimIntervalMs: number;
  /** Bat worker hay khong (cho phep tat trong test) */
  enabled: boolean;
}

export interface WebhookConfig {
  /**
   * WEBHOOK RIENG TU: `webhook authentication secret` copy trong
   * trang Cau hinh -> Thong bao -> Webhooks cua shop.
   */
  privateSecret: string;
  /** Map orgId -> secret, khi nhieu shop dung chung mot app. */
  privateOrgSecrets: Record<string, string>;

  /**
   * WEBHOOK KET NOI APP: app duoc cai dat vao shop, co buoc subscribe
   * (hub.verify_token / hub.challenge).
   */
  appVerifyToken: string;
  appClientSecret: string;
  appOrgSecrets: Record<string, string>;
}

export interface AppConfig {
  api: ApiConfig;
  webhook: WebhookConfig;
  credentials: {
    accessToken: string;
    orgId: number | null;
  };
  rule: RuleConfig;
  queue: QueueConfig;
}

function parseOrgSecrets(
  raw: string | undefined,
  name: string,
): Record<string, string> {
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`${name} phai la JSON hinh {"orgId":"secret"}`);
  }
}

export const appConfig = registerAs(
  'app',
  (): AppConfig => ({
    api: {
      baseUrl:
        process.env.HARAVAN_API_BASE_URL || 'https://apis.haravan.com/com',
      webhookBaseUrl:
        process.env.HARAVAN_WEBHOOK_API_BASE_URL ||
        'https://webhook.haravan.com',
      timeoutMs: Number(process.env.HARAVAN_API_TIMEOUT_MS || 10000),
      maxRetries: Number(process.env.HARAVAN_API_MAX_RETRIES || 3),
      retryBaseDelayMs: Number(process.env.HARAVAN_API_RETRY_DELAY_MS || 500),
      oauth: {
        clientId: process.env.HARAVAN_CLIENT_ID || '',
        clientSecret: process.env.HARAVAN_CLIENT_SECRET || '',
        redirectUri: process.env.HARAVAN_REDIRECT_URI || '',
      },
    },
    webhook: {
      privateSecret: process.env.HARAVAN_WEBHOOK_SECRET || '',
      privateOrgSecrets: parseOrgSecrets(
        process.env.HARAVAN_ORG_SECRETS,
        'HARAVAN_ORG_SECRETS',
      ),
      appVerifyToken: process.env.HARAVAN_APP_VERIFY_TOKEN || '',
      appClientSecret: process.env.HARAVAN_APP_CLIENT_SECRET || '',
      appOrgSecrets: parseOrgSecrets(
        process.env.HARAVAN_APP_ORG_SECRETS,
        'HARAVAN_APP_ORG_SECRETS',
      ),
    },
    credentials: {
      accessToken: process.env.HARAVAN_ACCESS_TOKEN || '',
      orgId: process.env.HARAVAN_ORG_ID
        ? Number(process.env.HARAVAN_ORG_ID)
        : null,
    },
    rule: {
      minPriorOrders: Number(process.env.HARAVAN_MIN_PRIOR_ORDERS || 1),
      minPriorSpent: Number(process.env.HARAVAN_MIN_PRIOR_SPENT || 0),
    },
    queue: {
      concurrency: Number(process.env.HARAVAN_QUEUE_CONCURRENCY || 5),
      maxAttempts: Number(process.env.HARAVAN_QUEUE_MAX_ATTEMPTS || 3),
      backoffBaseMs: Number(process.env.HARAVAN_QUEUE_BACKOFF_BASE_MS || 1000),
      backoffMaxMs: Number(process.env.HARAVAN_QUEUE_BACKOFF_MAX_MS || 30000),
      /** Bao lau poll co job moi */
      pollIntervalMs: Number(process.env.JOB_QUEUE_POLL_INTERVAL_MS || 1000),
      /** Bao lau worker nap lai heartbeat (nhip tim) */
      heartbeatIntervalMs: Number(
        process.env.JOB_QUEUE_HEARTBEAT_INTERVAL_MS || 4000,
      ),
      /** Worker giu job toi da lau thi job xem nhu worker da chet */
      leaseMs: Number(process.env.JOB_QUEUE_LEASE_MS || 90000),
      reclaimIntervalMs: Number(
        process.env.JOB_QUEUE_RECLAIM_INTERVAL_MS || 300000,
      ),
      /** Bat worker hay khong (cho phep tat trong test) */
      enabled: process.env.JOB_QUEUE_ENABLED !== 'false',
    },
  }),
);
