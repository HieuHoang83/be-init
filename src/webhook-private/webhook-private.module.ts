import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { appConfig } from '../config';
import { QueueModule } from '../queue/queue.module';
import { WebhookPrivateHmacGuard } from './webhook-private.guard';
import { WebhookPrivateController } from './webhook-private.controller';
import { WebhookPrivateService } from './webhook-private.service';
import {
  WebhookPrivateEvent,
  WebhookPrivateEventSchema,
} from './webhook-private.entity';

/** Tiếp nhận và lưu thông tin kiểm tra webhook. */
@Module({
  imports: [
    ConfigModule.forFeature(appConfig),
    QueueModule,
    MongooseModule.forFeature([
      { name: WebhookPrivateEvent.name, schema: WebhookPrivateEventSchema },
    ]),
  ],
  controllers: [WebhookPrivateController],
  providers: [WebhookPrivateService, WebhookPrivateHmacGuard],
  exports: [WebhookPrivateService, WebhookPrivateHmacGuard],
})
export class WebhookPrivateModule {}
