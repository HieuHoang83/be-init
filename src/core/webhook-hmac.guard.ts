import { CanActivate, ExecutionContext, Logger, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
import { verifyHmac, HMAC_HEADER } from './webhook-hmac.util';
import { readWebhookMeta } from './webhook-payload.util';
import { logWebhookPayload } from './webhook-payload-logger';

export interface HmacRequest extends Request {
  rawBody?: Buffer;
}

/** Header can xem khi debug */
function pickHeaders(headers: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (typeof value === 'string') out[key] = value;
  }
  return out;
}

/**
 * Base guard verify HMAC-SHA256 cua Harovan tren RAW BODY:
 *
 *   X-Haravan-Hmacsha256 = base64(HMAC_SHA256(raw_body, secret))
 *
 * Raw body bat buoc: Harovan ky tren byte-for-byte, JSON.stringify lai se
 * khac -> fail. `rawBody: true` da bat trong main.ts.
 *
 * Subclass implement `resolveSecret(orgId)` vi moi loai webhook lay secret
 * o noi khac nhau.
 */
export abstract class HmacGuard implements CanActivate {
  protected readonly logger = new Logger(this.constructor.name);

  /** 'app' | 'private' - de phan biet trong logs/webhook.log */
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

    /** Ghi log TRUOC khi verify - de request bi tu choi van con lai du lieu */
    const trace = (status: number, error?: string) =>
      logWebhookPayload({
        kind: this.logKind,
        // GET co hub.* = buoc verify_token. POST co HMAC = event that.
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

  /** Secret dung de ky HMAC cho shop nay. */
  protected abstract resolveSecret(
    orgId: number | null,
  ): string | null | Promise<string | null>;
}

