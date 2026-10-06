import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { appConfig } from '../config';
import { ApiModule } from '../api/api.module';
import { OrderModule } from '../order/order.module';
import { WebhookPrivateModule } from '../webhook-private/webhook-private.module';
import { WebhookAppController } from './webhook-app.controller';
import { WebhookAppManageController } from './webhook-app-manage.controller';
import { WebhookAppHmacGuard } from './webhook-app.guard';
import { WebhookOauthController } from './webhook-oauth.controller';
import { WebhookAppService } from './webhook-app.service';
import {
  AppInstallation,
  AppInstallationSchema,
  Shop,
  ShopSchema,
} from './webhook-app.entity';

/**
 * Webhook KET NOI APP: co buoc subscribe (hub.verify_token / hub.challenge).
 * Khac hoan toan voi webhook rieng tu o `webhook-private`.
 */
@Module({
  imports: [
    ConfigModule.forFeature(appConfig),
    ApiModule,
    OrderModule,
    // `WebhookPrivateService` la noi luu payload de worker tai lai.
    // App KHONG dung guard cua module nay - guard HMAC nam o controller rieng.
    WebhookPrivateModule,
    MongooseModule.forFeature([
      { name: AppInstallation.name, schema: AppInstallationSchema },
      { name: Shop.name, schema: ShopSchema },
    ]),
  ],
  controllers: [
    WebhookAppController,
    WebhookAppManageController,
    WebhookOauthController,
  ],
  providers: [WebhookAppService, WebhookAppHmacGuard],
  exports: [WebhookAppService, MongooseModule],
})
export class WebhookAppModule {}
