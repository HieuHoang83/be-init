import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { ApiModule } from '../api/api.module';
import { appConfig } from '../config';
import { QueueModule } from '../queue/queue.module';
import { WebhookPrivateModule } from '../webhook-private/webhook-private.module';
import { ShopSettingsModule } from '../shop-settings/shop-settings.module';
import { OrderController } from './order.controller';
import { OrderWorker } from './order.worker';
import { OrderService } from './order.service';
import {
  Order,
  OrderAction,
  OrderActionSchema,
  OrderEvent,
  OrderEventSchema,
  OrderSchema,
} from './order.entity';
import { Customer, CustomerSchema } from './customer.entity';

/** Module xử lý đơn hàng. */
@Module({
  imports: [
    ConfigModule.forFeature(appConfig),
    QueueModule,
    ApiModule,
    WebhookPrivateModule,
    ShopSettingsModule,
    MongooseModule.forFeature([
      { name: Order.name, schema: OrderSchema },
      { name: OrderAction.name, schema: OrderActionSchema },
      { name: OrderEvent.name, schema: OrderEventSchema },
      { name: Customer.name, schema: CustomerSchema },
    ]),
  ],
  controllers: [OrderController],
  providers: [OrderService, OrderWorker],
  exports: [OrderService],
})
export class OrderModule {}
