import { Inject, Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { ConfigType } from '@nestjs/config';
import { appConfig } from '../../config';
import {
  AppInstallation,
  AppInstallationDocument,
  AppWebhookStatus,
} from '../entities/webhook-app.entity';

/**
 * Lưu thông tin ứng dụng đã cài đặt, gồm client secret và verify token để
 * đăng ký webhook và xác thực HMAC.
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

  /** Lấy client secret dùng để xác thực HMAC cho ứng dụng đã cài đặt. */
  async resolveClientSecret(orgId: number): Promise<string | null> {
    const install = await this.findByOrg(orgId);
    if (install?.clientSecret) return install.clientSecret;

    const perOrg = this.orgSecrets[String(orgId)];
    if (perOrg) return perOrg;

    return this.envClientSecret || null;
  }

  /** Tạo bản ghi đang chờ khi ứng dụng đăng ký webhook. */
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

  /** Chuyển trạng thái sang hoạt động sau khi challenge hợp lệ. */
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

  /** Lưu các quyền shop đã cấp để kiểm tra và đối chiếu. */
  async upsertScopes(orgId: number, scopes: string[]): Promise<void> {
    await this.model
      .updateOne(
        { orgId },
        { $set: { scopes }, $setOnInsert: { orgId } },
        { upsert: true },
      )
      .exec();
  }

  async markUninstalled(orgId: number): Promise<void> {
    await this.model
      .updateOne(
        { orgId },
        {
          $set: {
            status: AppWebhookStatus.UNINSTALLED,
            uninstalledAt: new Date(),
          },
        },
      )
      .exec();
  }

  /** Đánh dấu ứng dụng đã đăng ký webhook thành công. */
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
   * So sánh verify token khi đăng ký webhook.
   * Ưu tiên token đã lưu theo shop, sau đó dùng token trong biến môi trường.
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
