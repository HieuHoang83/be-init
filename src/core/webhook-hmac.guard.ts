import { CanActivate, ExecutionContext, Logger, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
import { verifyHmac, HMAC_HEADER } from './webhook-hmac.util';
import { readWebhookMeta } from './webhook-payload.util';
import { logWebhookPayload } from './webhook-payload-logger';

export interface HmacRequest extends Request {
  rawBody?: Buffer;
}

/** Chỉ giữ lại các header cần xem khi kiểm tra lỗi. */
function pickHeaders(headers: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (typeof value === 'string') out[key] = value;
  }
  return out;
}

/**
 * Guard cơ sở xác thực HMAC-SHA256 của Haravan trên nội dung gốc:
 *
 *   X-Haravan-Hmacsha256 = base64(HMAC_SHA256(raw_body, secret))
 *
 * Phải dùng nội dung gốc vì Haravan ký theo từng byte; chuyển lại thành JSON
 * có thể làm thay đổi dữ liệu. `rawBody: true` đã được bật trong main.ts.
 *
 * Lớp kế thừa cài đặt `resolveSecret(orgId)` vì mỗi loại webhook lấy secret
 * từ một nơi khác nhau.
 */
export abstract class HmacGuard implements CanActivate {
  protected readonly logger = new Logger(this.constructor.name);

  /** Phân biệt webhook ứng dụng với webhook riêng tư trong log. */
  protected abstract readonly logKind: 'app' | 'private';

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<HmacRequest>();

    const signature = req.headers[HMAC_HEADER] as string | undefined;
    const raw = req.rawBody;
    const body = req.body as Record<string, unknown> | undefined;
    const meta = readWebhookMeta(req.headers, body);
    const topic = meta.topic;
    const orgId = meta.orgId;
    const picked = pickHeaders(req.headers);

    /** Ghi nhận yêu cầu trước khi xác thực để vẫn có dữ liệu khi bị từ chối. */
    const trace = (status: number, error?: string) =>
      logWebhookPayload({
        kind: this.logKind,
        // GET có hub.* là bước xác thực token; POST có HMAC là thông báo webhook.
        flow:
          status !== 200
            ? 'hmac_rejected'
            : req.query && (req.query['hub.challenge'] || req.query['code'])
              ? 'verify_token'
              : 'event_notification',
        method: req.method,
        path: req.originalUrl ?? req.url ?? null,
        topic,
        orgId,
        haravanOrderId: meta.orderId,
        status,
        raw: raw?.toString('utf8') ?? null,
        body,
        headers: picked,
        result: { isTest: meta.isTest },
        error,
      });

    if (!signature) {
      trace(401, 'thieu header ' + HMAC_HEADER);
      this.logger.warn(`Thieu header ${HMAC_HEADER}`);
      throw new UnauthorizedException('Thieu chu ky webhook');
    }

    if (!raw) {
      trace(401, 'khong co rawBody (thieu rawBody: true o main.ts)');
      this.logger.error('rawBody khong ton tai, can rawBody: true o main.ts');
      throw new UnauthorizedException('Khong doc duoc raw body');
    }

    const secret = await this.resolveSecret(orgId);
    if (!secret) {
      trace(401, `khong tim thay secret cho org ${orgId ?? 'null'}`);
      this.logger.error('Khong tim thay secret de verify webhook');
      throw new UnauthorizedException('Webhook chua duoc cau hinh');
    }

    if (!verifyHmac(raw, secret, signature)) {
      trace(401, 'HMAC khong khop');
      this.logger.warn('Chu ky webhook khong hop le');
      throw new UnauthorizedException('Chu ky webhook khong hop le');
    }

    trace(200);
    return true;
  }

  /** Lấy secret dùng để ký HMAC cho shop này. */
  protected abstract resolveSecret(
    orgId: number | null,
  ): string | null | Promise<string | null>;
}
