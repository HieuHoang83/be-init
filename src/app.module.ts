import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './user/user.module';
import { MongoModule } from '../mongo/mongo.module';
import { mongoConfig } from '../mongo/mongo.config';
import { appConfig } from './config';
import { ApiModule } from './api/api.module';
import { CustomerModule } from './customer/customer.module';
import { OrderModule } from './order/order.module';
import { QueueModule } from './queue/queue.module';
import { WebhookPrivateModule } from './webhook-private/webhook-private.module';
import { WebhookAppModule } from './webhook-app/webhook-app.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      // appConfig: webhooks + rule + queue + api
      // mongoConfig: URI/DB cho Mongoose
      load: [appConfig, mongoConfig],
      envFilePath: [
        '.env.local',
        '.env',
        'atlas-credentials.env',
        'dist/atlas-credentials.env',
      ],
    }),
    //gioi han luot goi api/ 1 may sd
    ThrottlerModule.forRoot([
      {
        ttl: 60000, //mili giay
        limit: 10, //gioi han trong n giay do
      },
    ]),
    UsersModule,
    AuthModule,
    // Data layer MongoDB
    MongoModule,
    // Don hang: luu DB, danh gia khach quay lai, goi confirm
    OrderModule,
    // Khach hang: thong ke so luong, danh sach, chi tiet
    CustomerModule,
    // Webhook Haravan: verify HMAC + audit
    WebhookPrivateModule,
    WebhookAppModule,
    // Hang doi cong viec: job luu trong MongoDB, worker chay tu phong
    QueueModule,
    // Client goi Haravan Omni API
    ApiModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
