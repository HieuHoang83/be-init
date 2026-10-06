import { Inject, Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { ConfigType } from '@nestjs/config';
import { appConfig } from '../config';
import {
  AppInstallation,
  AppInstallationDocument,
  AppWebhookStatus,
} from './webhook-app.entity';

/**
 * Luu thong tin app da cai dat: client secret + verify token cho luong
 * subscribe va verify HMAC cua WEBHOOK KET NOI APP.
 *
 * KHAC biet hoan toan voi webhook rieng tu (`webhook-private`):
 * - secret lay tu bang goc `app_installations` theo tung app da cai dat
 * - webhook rieng tu lay secret copy trong trang Thong bao cua shop
 */
@Injectable()
export class WebhookAppService {
  private readonly logger = new Logger(WebhookAppService.name);

  private readonly envVerifyToken: string;
  private readonly envClientSecret: string;
  private readonly orgSecrets: Record<string, string>;

  constructor(
    @InjectModel(AppInstallation.name)
    private readonly model: Model<AppInstallationDocument>,
    @Inject(appConfig.KEY) config: ConfigType<typeof appConfig>,
  ) {
    this.envVerifyToken = config.webhook.appVerifyToken;
    this.envClientSecret = config.webhook.appClientSecret;
    this.orgSecrets = config.webhook.appOrgSecrets;
  }

  async findByOrg(orgId: number): Promise<AppInstallationDocument | null> {
    return this.model.findOne({ orgId }).exec();
  }

  /** Client secret de verify HMAC cho app da cai dat. */
  async resolveClientSecret(orgId: number): Promise<string | null> {
    const install = await this.findByOrg(orgId);
    if (install?.clientSecret) return install.clientSecret;

    const perOrg = this.orgSecrets[String(orgId)];
    if (perOrg) return perOrg;

    return this.envClientSecret || null;
  }

  /** App gui subscribe: tao ban ghi pending cho org */
  async beginSubscription(params: {
    orgId: number;
    verifyToken: string;
    clientSecret?: string;
    shopName?: string;
  }): Promise<AppInstallationDocument> {
    const doc = await this.model
      .findOneAndUpdate(
        { orgId: params.orgId },
        {
          $set: {
            verifyToken: params.verifyToken,
            clientSecret: params.clientSecret ?? this.envClientSecret,
            shopName: params.shopName,
            status: AppWebhookStatus.PENDING,
          },
        },
        { upsert: true, new: true, setDefaultsOnInsert: true },
      )
      .exec();

    this.logger.log(`App subscription pending cho org ${params.orgId}`);
    return doc;
  }

  /** Challenge khop -> chuyen sang active */
  async confirmSubscription(
    orgId: number,
  ): Promise<AppInstallationDocument | null> {
    const doc = await this.model
      .findOneAndUpdate(
        { orgId },
        { $set: { status: AppWebhookStatus.ACTIVE, subscribedAt: new Date() } },
        { new: true },
      )
      .exec();

    if (doc) this.logger.log(`App subscription active cho org ${orgId}`);
    return doc;
  }

  /** Luu danh sach scope shop cap quyen, dung de audit va kiem tra `wh_api` */
  async upsertScopes(orgId: number, scopes: string[]): Promise<void> {
    await this.model
      .updateOne({ orgId }, { $set: { scopes }, $setOnInsert: { orgId } }, { upsert: true })
      .exec();
  }

  async markUninstalled(orgId: number): Promise<void> {
    await this.model
      .updateOne(
        { orgId },
        { $set: { status: AppWebhookStatus.UNINSTALLED, uninstalledAt: new Date() } },
      )
      .exec();
  }

  /** Buoc 4 thanh cong -> danh dau app da subscribe */
  async markSubscribed(orgId: number): Promise<void> {
    await this.model
      .updateOne(
        { orgId },
        { $set: { status: AppWebhookStatus.ACTIVE, subscribedAt: new Date() } },
        { upsert: true },
      )
      .exec();
  }

  /**
   * Verify token mong doi o buoc subscribe.
   * Uu tien token da luu theo org, fallback token trong env.
   */
  async verifySubscriptionToken(
    orgId: number | null,
    token: string,
  ): Promise<boolean> {
    if (orgId) {
      const install = await this.findByOrg(orgId);
      if (install?.verifyToken) return install.verifyToken === token;
    }
    return !!this.envVerifyToken && this.envVerifyToken === token;
  }
}
