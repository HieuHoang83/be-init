import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { QueueModule } from '../queue/queue.module';
import { elasticsearchConfig } from '../elasticsearch/elasticsearch.config';
import { ElasticsearchModule } from '../elasticsearch/elasticsearch.module';
import { HaravanCustomerModule } from '../haravan-customer/haravan-customer.module';
import { Customer, CustomerSchema } from '../order/entities/customer.entity';
import { Order, OrderSchema } from '../order/entities/order.entity';
import { CustomerController } from './customer.controller';
import { CustomerIndexBatcher } from './customer-index.batcher';
import { CustomerIndexService } from './customer-index.service';
import { CustomerSearchService } from './customer-search.service';
import { CustomerSyncWorker } from './customer-sync.worker';
import { CustomerActionWorker } from './customer-action.worker';
import { CustomerSyncService } from './customer-sync.service';
import { CustomerService } from './customer.service';

/** Cung cấp thống kê, danh sách, thông tin và đơn hàng của khách. */
@Module({
  imports: [
    QueueModule,
    ElasticsearchModule,
    // `CustomerIndexBatcher` can ngay cac nhan dem lenh ghi/chay lau de gom cong viec.
    ConfigModule.forFeature(elasticsearchConfig),
    HaravanCustomerModule,
    MongooseModule.forFeature([
      { name: Customer.name, schema: CustomerSchema },
      { name: Order.name, schema: OrderSchema },
    ]),
  ],
  controllers: [CustomerController],
  providers: [
    CustomerService,
    CustomerSearchService,
    CustomerIndexService,
    CustomerIndexBatcher,
    CustomerSyncService,
    CustomerActionWorker,
    CustomerSyncWorker,
  ],
  exports: [
    CustomerService,
    CustomerSearchService,
    CustomerIndexService,
    CustomerIndexBatcher,
    CustomerSyncService,
    MongooseModule,
  ],
})
export class CustomerModule {}
