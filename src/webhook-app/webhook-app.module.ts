import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { appConfig } from '../config';
import { ApiModule } from '../api/api.module';
import { OrderModule } from '../order/order.module';
import { QueueModule } from '../queue/queue.module';
import { WebhookPrivateModule } from '../webhook-private/webhook-private.module';
import { WebhookAppController } from './controllers/webhook-app.controller';
import { WebhookAppManageController } from './controllers/webhook-app-manage.controller';
import { WebhookAppHmacGuard } from './guards/webhook-app.guard';
import { WebhookOauthController } from './controllers/webhook-oauth.controller';
import { WebhookAppService } from './services/webhook-app.service';
import {
  AppInstallation,
  AppInstallationSchema,
  Shop,
  ShopSchema,
} from './entities/webhook-app.entity';

/**
 * Module nhận webhook của ứng dụng, đăng ký qua hub.verify_token và
 * hub.challenge. Khác với webhook riêng tư trong `webhook-private`.
 */
@Module({
  imports: [
    ConfigModule.forFeature(appConfig),
    ApiModule,
    OrderModule,
    QueueModule,
    // WebhookPrivateService lưu payload để worker tải lại.
    // Webhook ứng dụng dùng guard HMAC riêng trong controller của module này.
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
