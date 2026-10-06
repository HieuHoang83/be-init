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
      load: [appConfig, mongoConfig],
      envFilePath: '.env',
    }),
    ThrottlerModule.forRoot([
      {
        ttl: 60000,
        limit: 10,
      },
    ]),
    UsersModule,
    AuthModule,
    MongoModule,
    OrderModule,
    CustomerModule,
    WebhookPrivateModule,
    WebhookAppModule,
    QueueModule,
    ApiModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
