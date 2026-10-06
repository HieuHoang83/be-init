import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { Customer, CustomerSchema } from '../order/customer.entity';
import { Order, OrderSchema } from '../order/order.entity';
import { CustomerController } from './customer.controller';
import { CustomerService } from './customer.service';

/** Doc so lieu khach: thong ke, danh sach, chi tiet + don cua khach. */
@Module({
  imports: [
    MongooseModule.forFeature([
      { name: Customer.name, schema: CustomerSchema },
      { name: Order.name, schema: OrderSchema },
    ]),
  ],
  controllers: [CustomerController],
  providers: [CustomerService],
  exports: [CustomerService, MongooseModule],
})
export class CustomerModule {}
