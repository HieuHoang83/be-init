import { Inject, Injectable } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { HmacGuard } from '../core/webhook-hmac.guard';
import { appConfig } from '../config';
import { WebhookAppService } from './webhook-app.service';

/**
 * Verify HMAC cho WEBHOOK KET NOI APP.
 *
 * Khac webhook rieng tu: secret lay tu bang goc `app_installations`
 * (client secret cua app da cai dat), khong lay tu trang Thong bao.
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
    // Payload co org_id -> uu tien secret da luu cho app do
    if (orgId) {
      const secret = await this.appService.resolveClientSecret(orgId);
      if (secret) return secret;
    }

    // Khong co org_id (hoac chua co ban ghi) -> dung secret mac dinh,
    // phuc vu setup 1 shop, tranh cho moi payload deu phai co org_id.
    if (orgId) {
      const perOrg = this.orgSecrets[String(orgId)];
      if (perOrg) return perOrg;
    }

    return this.defaultSecret || null;
  }
}
