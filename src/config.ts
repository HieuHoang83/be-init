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

/**
 * Cau hinh OpenID Connect (Haravan Connect) de dang nhap bang tai khoan
 * Haravan thay vi tai khoan noi bo (so dien thoai + mat khau).
 *
 * Luong: GET /haravan/auth/login -> accounts.haravan.com/connect/authorize
 *        -> POST /haravan/auth/callback (form_post) -> tra JWT noi bo.
 */
export interface OpenIdConfig {
  /** Bat/tat co che dang nhap qua Haravan. */
  enabled: boolean;
  /** Issuer cua Haravan Connect, dung de lay OpenID Configuration. */
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** Phai trung tuyet doi voi redirect_uri da dang ky tren Partner Dashboard. */
  redirectUri: string;
  /**
   * Noi chuyen huong trinh duyet sau khi doi code thanh cong.
   * De trong thi callback tra JSON (dung cho mobile / test bang Postman).
   */
  frontendRedirectUri: string;
  /** Scope yeu cau; `openid` la bat buoc, profile/email de lay thong tin nguoi dung. */
  scope: string;
  /**
   * `code` (mac dinh) la Authorization Code Flow + PKCE.
   * Doi neu Partner Dashboard yeu cau `code id_token` (hybrid flow).
   */
  responseType: string;
  /** Tu tao user noi bo o lan dang nhap dau tien neu chua lien ket. */
  autoProvision: boolean;
  /** Vai tro gan cho user vua tao; phai ton tai trong collection `roles`. */
  defaultRole: string;
  /**
   * Chi cho phep tai khoan Haravan thuoc shop nay dang nhap.
   * 0/null = cho phep moi shop.
   */
  orgId: number | null;
  /** Thoi gian song cua state/nonce va cua ma doi token mot lan (ms). */
  stateTtlMs: number;
  /**
   * Host duoc phep nham trong `redirect_uri` gui len tu frontend.
   * De trong thi bo qua kiem tra (chi nen dung o moi truong dev).
   */
  allowedRedirectHosts: string[];
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
  openid: OpenIdConfig;
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
    openid: {
      enabled: process.env.HARAVAN_OPENID_ENABLED !== 'false',
      issuer:
        process.env.HARAVAN_OPENID_ISSUER || 'https://accounts.haravan.com',
      clientId:
        process.env.HARAVAN_OPENID_CLIENT_ID ||
        process.env.HARAVAN_CLIENT_ID ||
        '',
      clientSecret:
        process.env.HARAVAN_OPENID_CLIENT_SECRET ||
        process.env.HARAVAN_CLIENT_SECRET ||
        '',
      redirectUri: process.env.HARAVAN_OPENID_REDIRECT_URI || '',
      frontendRedirectUri:
        process.env.HARAVAN_OPENID_FRONTEND_REDIRECT_URI || '',
      // `org` de id_token co them `orgid` (shop cua nguoi dung dang nhap).
      scope: process.env.HARAVAN_OPENID_SCOPE || 'openid profile email org',
      responseType: process.env.HARAVAN_OPENID_RESPONSE_TYPE || 'code',
      autoProvision: process.env.HARAVAN_OPENID_AUTO_PROVISION !== 'false',
      defaultRole: process.env.HARAVAN_OPENID_DEFAULT_ROLE || 'Assistant Admin',
      orgId: process.env.HARAVAN_OPENID_ORG_ID
        ? Number(process.env.HARAVAN_OPENID_ORG_ID)
        : null,
      stateTtlMs: Number(process.env.HARAVAN_OPENID_STATE_TTL_MS || 600000),
      allowedRedirectHosts: (
        process.env.HARAVAN_OPENID_ALLOWED_REDIRECT_HOSTS || ''
      )
        .split(',')
        .map((host) => host.trim())
        .filter(Boolean),
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
