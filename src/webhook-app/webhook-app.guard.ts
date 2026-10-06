import { Inject, Injectable } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { HmacGuard } from '../core/webhook-hmac.guard';
import { appConfig } from '../config';
import { WebhookAppService } from './webhook-app.service';

/**
 * Xác thực HMAC cho webhook ứng dụng.
 * Secret lấy từ `app_installations`, không lấy từ trang Thông báo của shop.
 */
@Injectable()
export class WebhookAppHmacGuard extends HmacGuard {
  protected readonly logKind = 'app' as const;

  private readonly defaultSecret: string;
  private readonly orgSecrets: Record<string, string>;

  constructor(
    private readonly appService: WebhookAppService,
    @Inject(appConfig.KEY) config: ConfigType<typeof appConfig>,
  ) {
    super();
    this.defaultSecret = config.webhook.appClientSecret;
    this.orgSecrets = config.webhook.appOrgSecrets;
  }

  protected async resolveSecret(orgId: number | null): Promise<string | null> {
    // Nếu payload có org_id, ưu tiên secret đã lưu cho ứng dụng đó.
    if (orgId) {
      const secret = await this.appService.resolveClientSecret(orgId);
      if (secret) return secret;
    }

    // Nếu chưa có secret theo shop, dùng secret mặc định để hỗ trợ cấu hình một shop.
    if (orgId) {
      const perOrg = this.orgSecrets[String(orgId)];
      if (perOrg) return perOrg;
    }

    return this.defaultSecret || null;
  }
}
