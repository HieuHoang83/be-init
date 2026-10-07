import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

/** Loại webhook: private được cấu hình trong trang quản trị; app được đăng ký từ ứng dụng. */
export enum AppWebhookStatus {
  ACTIVE = 'active',
  UNINSTALLED = 'uninstalled',
  PENDING = 'pending',
}

@Schema({ collection: 'app_installations', timestamps: true })
export class AppInstallation {
  @Prop({ required: true })
  orgId!: number;

  @Prop({ required: true })
  shopName?: string;

  @Prop()
  shopDomain?: string;

  @Prop()
  ownerEmail?: string;

  /**
   * Client secret của ứng dụng, khác với secret webhook riêng tư.
   * Dùng để xác thực HMAC khi ứng dụng gửi webhook.
   */
  @Prop({ required: true })
  clientSecret!: string;

  /** Token ứng dụng gửi khi đăng ký, dùng để xác thực challenge. */
  @Prop({ required: true })
  verifyToken!: string;

  @Prop({ type: [String], default: [] })
  scopes?: string[];

  @Prop({
    type: String,
    enum: AppWebhookStatus,
    default: AppWebhookStatus.PENDING,
  })
  status!: AppWebhookStatus;

  @Prop()
  subscribedAt?: Date;

  @Prop()
  uninstalledAt?: Date;
}
export type AppInstallationDocument = HydratedDocument<AppInstallation>;

export const AppInstallationSchema =
  SchemaFactory.createForClass(AppInstallation);

AppInstallationSchema.index({ orgId: 1 }, { unique: true });

/** Thông tin shop và dữ liệu xác thực Omni API của shop. */
@Schema({ collection: 'shops', timestamps: true })
export class Shop {
  @Prop({ required: true })
  orgId!: number;

  @Prop()
  name?: string;

  @Prop()
  domain?: string;

  @Prop()
  ownerEmail?: string;

  @Prop()
  apiKey?: string;

  @Prop()
  apiSecret?: string;

  /**
   * Access token nhận từ callback OAuth ở bước 3. Ưu tiên token này;
   * nếu chưa có thì dùng HARAVAN_ACCESS_TOKEN trong biến môi trường.
   */
  @Prop({ select: false })
  accessToken?: string;

  @Prop()
  accessTokenExpiresAt?: Date;

  @Prop({ type: [String], default: [] })
  scopes?: string[];
}
export type ShopDocument = HydratedDocument<Shop>;

export const ShopSchema = SchemaFactory.createForClass(Shop);

ShopSchema.index({ orgId: 1 }, { unique: true });
