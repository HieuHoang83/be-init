import {
  BadGatewayException,
  Injectable,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { Inject } from '@nestjs/common';
import { appConfig } from '../config';
import { OrderPayload } from '../interface/order.interface';
import {
  SubscribedWebhookListResponse,
  WebhookSubscribeResponse,
} from '../webhook-app/webhook-app.interface';
import { AccessTokenStore } from './access-token.store';

export interface OAuthTokenResponse {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

export interface ApiResponse<T = unknown> {
  body: T;
  statusCode: number;
  durationMs: number;
}

interface ErrorBody {
  errors?: string[];
  message?: string;
}

/** Loi tu Harovan, giu nguyen status de service layer quyet dinh retry hay khong */
export class ApiError extends Error {
  constructor(
    readonly statusCode: number,
    message: string,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }

  /** 429 / 5xx / loi mang -> nen retry */
  get retryable(): boolean {
    if (this.statusCode === 429) return true;
    return this.statusCode >= 500 && this.statusCode < 600;
  }
}

/**
 * Client goi Haravan Omni API bang `fetch` co san cua Node 18+.
 * - Tu lay access token theo shop
 * - Retry co backoff khi gap 429 / 5xx / loi mang
 * - Nem ApiError de OrderService phan loai
 */
@Injectable()
export class ApiClient {
  private readonly logger = new Logger(ApiClient.name);

  private readonly cfg: ConfigType<typeof appConfig>['api'];

  constructor(
    @Inject(appConfig.KEY) private readonly config: ConfigType<typeof appConfig>,
    private readonly tokenStore: AccessTokenStore,
  ) {
    this.cfg = config.api;
  }

  getOrder(orgId: number, orderId: number): Promise<ApiResponse<OrderPayload>> {
    return this.request<OrderPayload>(orgId, 'GET', `/orders/${orderId}.json`);
  }

  listOrders(
    orgId: number,
    params: Record<string, string | number> = {},
  ): Promise<ApiResponse<unknown>> {
    return this.request<unknown>(orgId, 'GET', '/orders.json', undefined, params);
  }

  /**
   * Xac nhan don: POST /com/orders/{order_id}/confirm.json
   * Body: { confirmed_status: 'confirmed' }
   */
  confirmOrder(orgId: number, orderId: number): Promise<ApiResponse<unknown>> {
    return this.request<unknown>(orgId, 'POST', `/orders/${orderId}/confirm.json`, {
      confirmed_status: 'confirmed',
    });
  }

  /**
   * Buoc 4 - POST https://webhook.haravan.com/api/subscribe
   * Khai bao app duoc nhan thong bao webhook. Can scope `wh_api`.
   * KHAC Omni API: host khac va dung `Authorization: Bearer` (khong phai
   * header haravan-access-token).
   */
  subscribeWebhook(orgId: number): Promise<ApiResponse<WebhookSubscribeResponse>> {
    return this.requestWebhookApi<WebhookSubscribeResponse>(orgId, 'POST');
  }

  /** Buoc 7 - DELETE https://webhook.haravan.com/api/subscribe */
  unsubscribeWebhook(orgId: number): Promise<ApiResponse<WebhookSubscribeResponse>> {
    return this.requestWebhookApi<WebhookSubscribeResponse>(orgId, 'DELETE');
  }

  /** Buoc 8 - GET https://webhook.haravan.com/api/subscribe */
  listSubscribedWebhooks(
    orgId: number,
  ): Promise<ApiResponse<SubscribedWebhookListResponse>> {
    return this.requestWebhookApi<SubscribedWebhookListResponse>(orgId, 'GET');
  }

  /**
   * Buoc 3 - doi authorization code lay access token.
   * POST https://accounts.haravan.com/connect/token
   *
   * KHONG dung AccessTokenStore: buoc nay chua co org_id va chua co token,
   * truyền client_id + client_secret + code + redirect_uri trực tiếp.
   */
  async exchangeAuthorizationCode(
    code: string,
  ): Promise<ApiResponse<OAuthTokenResponse>> {
    const url = 'https://accounts.haravan.com/connect/token';
    const startedAt = Date.now();

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.cfg.oauth.clientId,
      client_secret: this.cfg.oauth.clientSecret,
      code,
      // Phai GION CHINH XAC redirect_uri dung o buoc authorize (Step 2),
      // neu lech 1 ky tu -> invalid_grant
      redirect_uri: this.cfg.oauth.redirectUri,
    });

    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), this.cfg.timeoutMs);
    let res: Response;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body: body.toString(),
        signal: abort.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    const text = await res.text();
    const durationMs = Date.now() - startedAt;

    let json: OAuthTokenResponse & { error?: string; error_description?: string };
    try {
      json = JSON.parse(text);
    } catch {
      throw new ApiError(res.status, 'Response tu /connect/token khong phai JSON', text);
    }

    if (!res.ok || json.error || !json.access_token) {
      throw new ApiError(
        res.status,
        `Doi code that bai: ${json.error ?? 'khong co access_token'}` +
          (json.error_description ? ` - ${json.error_description}` : ''),
        json,
      );
    }

    return { body: json, statusCode: res.status, durationMs };
  }

  private async requestWebhookApi<T>(
    orgId: number,
    method: 'GET' | 'POST' | 'DELETE',
  ): Promise<ApiResponse<T>> {
    const url = new URL(`${this.cfg.webhookBaseUrl}/api/subscribe`);
    const startedAt = Date.now();
    const token = await this.tokenStore.get(orgId);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.cfg.timeoutMs);

    try {
      const res = await fetch(url, {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          accept: 'application/json',
        },
        signal: controller.signal,
      });

      const text = await res.text().catch(() => '');
      const parsed = safeJson(text) as ErrorBody | undefined;

      if (!res.ok) {
        const message =
          parsed?.errors?.[0] ??
          parsed?.message ??
          `Harovan webhook API tra ${res.status}`;
        throw new ApiError(res.status, message, parsed ?? text);
      }

      this.logger.log(
        `${method} ${url.pathname} -> ${res.status} (org ${orgId})`,
      );

      return {
        body: parsed as T,
        statusCode: res.status,
        durationMs: Date.now() - startedAt,
      };
    } catch (error) {
      if (error instanceof ApiError) throw error;
      const message = (error as Error).message;
      throw new ServiceUnavailableException(
        `Khong goi duoc Harovan webhook API: ${message}`,
      );
    } finally {
      clearTimeout(timer);
    }
  }

  private async request<T>(
    orgId: number,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    path: string,
    body?: Record<string, unknown>,
    params?: Record<string, string | number>,
  ): Promise<ApiResponse<T>> {
    const url = new URL(`${this.cfg.baseUrl}${path}`);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        url.searchParams.set(key, String(value));
      }
    }

    let lastError: ApiError | null = null;

    for (let attempt = 1; attempt <= this.cfg.maxRetries; attempt++) {
      const startedAt = Date.now();
      const token = await this.tokenStore.get(orgId);

      try {
        const res = await this.fetchWithTimeout(url, method, token, body);

        if (!res.ok) {
          const text = await res.text().catch(() => '');
          const parsed = safeJson(text) as ErrorBody | undefined;
          const message =
            parsed?.errors?.[0] ??
            parsed?.message ??
            `Harovan API tra ${res.status}`;

          lastError = new ApiError(res.status, message, parsed ?? text);
          if (!lastError.retryable || attempt === this.cfg.maxRetries) {
            throw lastError;
          }

          this.logger.warn(
            `${method} ${url.pathname} -> ${res.status}, retry ${attempt}/${this.cfg.maxRetries}`,
          );
          await this.sleep(this.cfg.retryBaseDelayMs * 2 ** (attempt - 1));
          continue;
        }

        const text = await res.text();
        return {
          body: safeJson(text) as T,
          statusCode: res.status,
          durationMs: Date.now() - startedAt,
        };
      } catch (error) {
        if (error instanceof ApiError) {
          if (!error.retryable || attempt === this.cfg.maxRetries) throw error;
          lastError = error;
          continue;
        }

        // Loi mang / timeout -> luon retry
        const message = (error as Error).message;
        lastError = new ApiError(0, `Khong goi duoc Haravan API: ${message}`);

        if (attempt === this.cfg.maxRetries) {
          throw new ServiceUnavailableException(lastError.message);
        }

        this.logger.warn(
          `${method} ${url.pathname} loi mang (${message}), retry ${attempt}/${this.cfg.maxRetries}`,
        );
        await this.sleep(this.cfg.retryBaseDelayMs * 2 ** (attempt - 1));
      }
    }

    throw new BadGatewayException(
      lastError?.message ?? 'Haravan API khong phan hoi',
    );
  }

  private async fetchWithTimeout(
    url: URL,
    method: string,
    token: string,
    body?: Record<string, unknown>,
  ): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.cfg.timeoutMs);

    try {
      return await fetch(url, {
        method,
        headers: {
          // Token tu OAuth App install chi chap nhan `Authorization: Bearer`.
          // Token long-lived (kieu cu) lai dung `haravan-access-token`.
          // Gui ca hai de an toan cho moi hinh cap quyen.
          'haravan-access-token': token,
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          accept: 'application/json',
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

function safeJson(text: string): unknown {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
