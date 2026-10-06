import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { ApiModule } from '../api/api.module';
import { appConfig } from '../config';
import { QueueModule } from '../queue/queue.module';
import { WebhookPrivateModule } from '../webhook-private/webhook-private.module';
import { OrderController } from './order.controller';
import { OrderWorker } from './order.worker';
import { OrderService } from './order.service';
import {
  Order,
  OrderAction,
  OrderActionSchema,
  OrderSchema,
} from './order.entity';
import { Customer, CustomerSchema } from './customer.entity';

/** Luu don, danh gia rule khach quay lai, xac nhan don. */
@Module({
  imports: [
    ConfigModule.forFeature(appConfig),
    QueueModule,
    ApiModule,
    WebhookPrivateModule,
    MongooseModule.forFeature([
      { name: Order.name, schema: OrderSchema },
      { name: OrderAction.name, schema: OrderActionSchema },
      { name: Customer.name, schema: CustomerSchema },
    ]),
  ],
  controllers: [OrderController],
  providers: [OrderService, OrderWorker],
  exports: [OrderService],
})
export class OrderModule {}
