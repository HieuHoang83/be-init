import { registerAs } from '@nestjs/config';

export interface RuleConfig {
  /** Số đơn tối thiểu khách đã mua trước đơn hiện tại để tự động xác nhận. */
  minPriorOrders: number;
  /** Tổng chi tiêu tối thiểu trước đơn này (VND). 0 = bỏ qua. */
  minPriorSpent: number;
}

export interface ApiConfig {
  baseUrl: string;
  /** Địa chỉ API đăng ký webhook; máy chủ này khác Omni API. */
  webhookBaseUrl: string;
  timeoutMs: number;
  maxRetries: number;
  retryBaseDelayMs: number;
  /** Cấu hình OAuth để đổi mã ủy quyền lấy access token ở bước 3. */
  oauth: OAuthConfig;
}

export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  /** Phải giống hệt redirect_uri đã dùng ở bước cấp quyền. */
  redirectUri: string;
}

export interface QueueConfig {
  concurrency: number;
  maxAttempts: number;
  backoffBaseMs: number;
  backoffMaxMs: number;
  /** Thời gian chờ giữa các lần tìm công việc mới. */
  pollIntervalMs: number;
  /** Khoảng thời gian worker gia hạn tín hiệu còn hoạt động. */
  heartbeatIntervalMs: number;
  /** Thời gian giữ công việc tối đa trước khi xem worker là đã dừng. */
  leaseMs: number;
  /** Khoảng thời gian quét công việc quá hạn tín hiệu hoạt động. */
  reclaimIntervalMs: number;
  /** Bật hoặc tắt worker, chủ yếu dùng trong kiểm thử. */
  enabled: boolean;
}

export interface WebhookConfig {
  /**
   * Webhook riêng tư: secret lấy tại Cấu hình -> Thông báo -> Webhooks của shop.
   */
  privateSecret: string;
  /** Ánh xạ mã shop sang secret khi nhiều shop dùng chung một ứng dụng. */
  privateOrgSecrets: Record<string, string>;

  /**
   * Webhook ứng dụng: ứng dụng được cài vào shop và đăng ký qua
   * hub.verify_token / hub.challenge.
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
      /** Thời gian chờ giữa các lần tìm công việc mới. */
      pollIntervalMs: Number(process.env.JOB_QUEUE_POLL_INTERVAL_MS || 1000),
      /** Khoảng thời gian worker gia hạn tín hiệu còn hoạt động. */
      heartbeatIntervalMs: Number(
        process.env.JOB_QUEUE_HEARTBEAT_INTERVAL_MS || 4000,
      ),
      /** Thời gian giữ công việc tối đa trước khi xem worker là đã dừng. */
      leaseMs: Number(process.env.JOB_QUEUE_LEASE_MS || 90000),
      reclaimIntervalMs: Number(
        process.env.JOB_QUEUE_RECLAIM_INTERVAL_MS || 300000,
      ),
      /** Bật hoặc tắt worker, chủ yếu dùng trong kiểm thử. */
      enabled: process.env.JOB_QUEUE_ENABLED !== 'false',
    },
  }),
);
