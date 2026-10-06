import { Inject } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { HmacGuard } from '../core/webhook-hmac.guard';
import { appConfig } from '../config';

/**
 * Xác thực HMAC cho webhook riêng tư.
 *
 * Secret lấy tại Cấu hình -> Thông báo -> Webhooks trong trang quản trị.
 * Loại webhook này không cần bước đăng ký.
 */
export class WebhookPrivateHmacGuard extends HmacGuard {
  protected readonly logKind = 'private' as const;

  private readonly fallbackSecret: string;
  private readonly orgSecrets: Record<string, string>;

  constructor(@Inject(appConfig.KEY) config: ConfigType<typeof appConfig>) {
    super();
    this.fallbackSecret = config.webhook.privateSecret;
    this.orgSecrets = config.webhook.privateOrgSecrets;
  }

  protected resolveSecret(orgId: number | null): string | null {
    if (orgId) {
      const secret = this.orgSecrets[String(orgId)];
      if (secret) return secret;
    }
    return this.fallbackSecret || null;
  }
}
