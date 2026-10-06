import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

/** Loai webhook: private = chu danh tay trong trang quan tri, app = app da cai dat */
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
   * Client secret cua app (khac webhook authentication secret cua
   * webhook rieng tu). Dung de verify HMAC khi app goi webhook.
   */
  @Prop({ required: true })
  clientSecret!: string;

  /** verify_token app tra ve o buoc subscribe, dung de xac nhan challenge */
  @Prop({ required: true })
  verifyToken!: string;

  @Prop({ type: [String], default: [] })
  scopes?: string[];

  @Prop({ type: String, enum: AppWebhookStatus, default: AppWebhookStatus.PENDING })
  status!: AppWebhookStatus;

  @Prop()
  subscribedAt?: Date;

  @Prop()
  uninstalledAt?: Date;
}
export type AppInstallationDocument = HydratedDocument<AppInstallation>;

export const AppInstallationSchema = SchemaFactory.createForClass(AppInstallation);

AppInstallationSchema.index({ orgId: 1 }, { unique: true });

/** Thong tin shop + thong tin xac thuc Omni API cua shop */
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
   * Access token lay tu OAuth callback (Step 3). Uu tien dung token nay,
   * fallback HARAVAN_ACCESS_TOKEN trong env khi rong.
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
