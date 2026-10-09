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
} from '../webhook-app/interfaces/webhook-app.interface';
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
  /** Haravan tra `errors` co the la chuoi, mang chuoi hoac object {field: loi}. */
  errors?: string | string[] | Record<string, unknown>;
  message?: string;
}

/** Lay noi dung loi tu body loi cua Haravan (khong bi cat chuoi thanh 1 ky tu). */
function readApiErrorMessage(
  parsed: ErrorBody | undefined,
  status: number,
  fallback: string,
): string {
  const errors = parsed?.errors;
  if (typeof errors === 'string' && errors.trim()) return errors;
  if (Array.isArray(errors)) {
    const first = errors.find((item) => typeof item === 'string' && item);
    if (first) return first;
  }
  if (errors && typeof errors === 'object') {
    const first = Object.values(errors).find(
      (item) => typeof item === 'string' && item,
    );
    if (first) return first as string;
  }
  if (typeof parsed?.message === 'string' && parsed.message.trim()) {
    return parsed.message;
  }
  return `${fallback} ${status}`;
}

/** Lỗi từ Haravan; giữ nguyên mã trạng thái để tầng dịch vụ quyết định có thử lại hay không. */
export class ApiError extends Error {
  constructor(
    readonly statusCode: number,
    message: string,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }

  /** Nên thử lại khi gặp mã 429, lỗi máy chủ 5xx hoặc lỗi mạng. */
  get retryable(): boolean {
    if (this.statusCode === 429) return true;
    return this.statusCode >= 500 && this.statusCode < 600;
  }
}

/**
 * Gọi Haravan Omni API bằng `fetch` có sẵn trong Node.js 18 trở lên.
 * - Tự lấy access token theo shop.
 * - Thử lại với thời gian chờ tăng dần khi gặp lỗi 429, 5xx hoặc lỗi mạng.
 * - Ném ApiError để OrderService phân loại lỗi.
 */
@Injectable()
export class ApiClient {
  private readonly logger = new Logger(ApiClient.name);

  private readonly cfg: ConfigType<typeof appConfig>['api'];

  constructor(
    @Inject(appConfig.KEY)
    private readonly config: ConfigType<typeof appConfig>,
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
    return this.request<unknown>(
      orgId,
      'GET',
      '/orders.json',
      undefined,
      params,
    );
  }

  /**
   * Xác nhận đơn hàng qua POST /com/orders/{order_id}/confirm.json.
   * Nội dung gửi đi: { confirmed_status: 'confirmed' }.
   */
  confirmOrder(orgId: number, orderId: number): Promise<ApiResponse<unknown>> {
    return this.request<unknown>(
      orgId,
      'POST',
      `/orders/${orderId}/confirm.json`,
      {
        confirmed_status: 'confirmed',
      },
    );
  }

  /**
   * Hủy đơn: POST /com/orders/{order_id}/cancel.json
   * `amount` là số tiền hoàn lại (bỏ trống = hoàn toàn bộ), `refund` chỉ dùng khi
   * đơn đã capture; `restock` trả lại tồn kho.
   */
  cancelOrder(
    orgId: number,
    orderId: number,
    body: Record<string, unknown> = {},
  ): Promise<ApiResponse<unknown>> {
    return this.request<unknown>(
      orgId,
      'POST',
      `/orders/${orderId}/cancel.json`,
      body,
    );
  }

  /** Đóng đơn: POST /com/orders/{order_id}/close.json */
  closeOrder(
    orgId: number,
    orderId: number,
    body: Record<string, unknown> = {},
  ): Promise<ApiResponse<unknown>> {
    return this.request<unknown>(
      orgId,
      'POST',
      `/orders/${orderId}/close.json`,
      body,
    );
  }

  /** Mở lại đơn đã đóng: POST /com/orders/{order_id}/open.json */
  openOrder(
    orgId: number,
    orderId: number,
    body: Record<string, unknown> = {},
  ): Promise<ApiResponse<unknown>> {
    return this.request<unknown>(
      orgId,
      'POST',
      `/orders/${orderId}/open.json`,
      body,
    );
  }

  /**
   * Cập nhật đơn: PUT /com/orders/{order_id}.json
   * Haravan không cho sửa line_items / số lượng / financial_status.
   */
  updateOrder(
    orgId: number,
    orderId: number,
    body: Record<string, unknown>,
  ): Promise<ApiResponse<OrderPayload>> {
    return this.request<OrderPayload>(
      orgId,
      'PUT',
      `/orders/${orderId}.json`,
      body,
    );
  }

  /** Danh sách giao dịch hoàn tiền: GET /com/orders/{order_id}/refunds.json */
  listRefunds(
    orgId: number,
    orderId: number,
    page = 1,
    limit = 20,
  ): Promise<ApiResponse<unknown>> {
    return this.request<unknown>(
      orgId,
      'GET',
      `/orders/${orderId}/refunds.json`,
      undefined,
      { page, limit },
    );
  }

  /** Chi tiết một giao dịch hoàn tiền: GET /com/orders/{order_id}/refunds/{refund_id}.json */
  getRefund(
    orgId: number,
    orderId: number,
    refundId: number,
  ): Promise<ApiResponse<unknown>> {
    return this.request<unknown>(
      orgId,
      'GET',
      `/orders/${orderId}/refunds/${refundId}.json`,
    );
  }

  /** Hoàn tiền: POST /com/orders/{order_id}/refunds.json */
  createRefund(
    orgId: number,
    orderId: number,
    body: Record<string, unknown>,
  ): Promise<ApiResponse<unknown>> {
    return this.request<unknown>(
      orgId,
      'POST',
      `/orders/${orderId}/refunds.json`,
      body,
    );
  }

  /** Danh sách giao dịch của đơn: GET /com/orders/{order_id}/transactions.json */
  listTransactions(
    orgId: number,
    orderId: number,
    params: Record<string, string | number> = {},
  ): Promise<ApiResponse<unknown>> {
    return this.request<unknown>(
      orgId,
      'GET',
      `/orders/${orderId}/transactions.json`,
      undefined,
      params,
    );
  }

  /**
   * Chi tiết một giao dịch:
   * GET /com/orders/{order_id}/transactions/{transaction_id}.json
   */
  getTransaction(
    orgId: number,
    orderId: number,
    transactionId: number,
    params: Record<string, string | number> = {},
  ): Promise<ApiResponse<unknown>> {
    return this.request<unknown>(
      orgId,
      'GET',
      `/orders/${orderId}/transactions/${transactionId}.json`,
      undefined,
      params,
    );
  }

  /** Tạo giao dịch (thanh toán): POST /com/orders/{order_id}/transactions.json */
  createTransaction(
    orgId: number,
    orderId: number,
    body: Record<string, unknown>,
  ): Promise<ApiResponse<unknown>> {
    return this.request<unknown>(
      orgId,
      'POST',
      `/orders/${orderId}/transactions.json`,
      body,
    );
  }

  /**
   * Gọi Omni API tùy ý (`/com/{path}`). Dùng cho Product, Customer và resource
   * khác theo tài liệu Haravan.
   */
  call<T = unknown>(
    orgId: number,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    path: string,
    body?: Record<string, unknown>,
    params?: Record<string, string | number>,
  ): Promise<ApiResponse<T>> {
    return this.request<T>(orgId, method, path, body, params);
  }

  /**
   * Bước 4: đăng ký để ứng dụng nhận webhook. Cần quyền `wh_api`.
   * API này dùng máy chủ riêng và xác thực bằng `Authorization: Bearer`,
   * không dùng header `haravan-access-token` như Omni API.
   */
  subscribeWebhook(
    orgId: number,
  ): Promise<ApiResponse<WebhookSubscribeResponse>> {
    return this.requestWebhookApi<WebhookSubscribeResponse>(orgId, 'POST');
  }

  /** Bước 7: hủy đăng ký webhook. */
  unsubscribeWebhook(
    orgId: number,
  ): Promise<ApiResponse<WebhookSubscribeResponse>> {
    return this.requestWebhookApi<WebhookSubscribeResponse>(orgId, 'DELETE');
  }

  /** Bước 8: lấy danh sách webhook đã đăng ký. */
  listSubscribedWebhooks(
    orgId: number,
  ): Promise<ApiResponse<SubscribedWebhookListResponse>> {
    return this.requestWebhookApi<SubscribedWebhookListResponse>(orgId, 'GET');
  }

  /**
   * Bước 3: đổi mã ủy quyền lấy access token qua
   * POST https://accounts.haravan.com/connect/token.
   *
   * Không dùng AccessTokenStore vì bước này chưa có org_id hay token.
   * Gửi trực tiếp client_id, client_secret, code và redirect_uri.
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
      // redirect_uri phải giống hệt URI ở bước cấp quyền, nếu không sẽ lỗi invalid_grant.
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

    let json: OAuthTokenResponse & {
      error?: string;
      error_description?: string;
    };
    try {
      json = JSON.parse(text);
    } catch {
      throw new ApiError(
        res.status,
        'Response tu /connect/token khong phai JSON',
        text,
      );
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
        const message = readApiErrorMessage(
          parsed,
          res.status,
          'Harovan webhook API tra',
        );
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
          const message = readApiErrorMessage(
            parsed,
            res.status,
            'Harovan API tra',
          );

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

        // Luôn thử lại nếu xảy ra lỗi mạng hoặc hết thời gian chờ.
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
          // OAuth App dùng `Authorization: Bearer`; token cũ dùng
          // `haravan-access-token`. Gửi cả hai để hỗ trợ các kiểu cấp quyền.
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
