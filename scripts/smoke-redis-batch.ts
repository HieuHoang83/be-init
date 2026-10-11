/**
 * Kiem tra duong ghi that cua bo dem Redis: Mongo -> Redis -> Elasticsearch.
 *
 * Chay: npx ts-node -r tsconfig-paths/register scripts/smoke-redis-batch.ts
 */
import { Test } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { MongoModule } from '../mongo/mongo.module';
import { mongoConfig } from '../mongo/mongo.config';
import { appConfig } from '../src/config';
import { QueueModule } from '../src/queue/queue.module';
import { ApiModule } from '../src/api/api.module';
import { CustomerModule } from '../src/customer/customer.module';
import { WebhookPrivateModule } from '../src/webhook-private/webhook-private.module';
import { getModelToken } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Customer } from '../src/order/entities/customer.entity';
import { CustomerIndexBatcher } from '../src/customer/customer-index.batcher';
import Redis from 'ioredis';

async function main(): Promise<void> {
  const ref = await Test.createTestingModule({
    imports: [
      ConfigModule.forRoot({
        isGlobal: true,
        load: [appConfig, mongoConfig],
        envFilePath: '.env',
      }),
      MongoModule,
      QueueModule,
      ApiModule,
      WebhookPrivateModule,
      CustomerModule,
    ],
  }).compile();

  const app = ref.createNestApplication();
  await app.init();

  const customers = app.get<Model<Customer>>(getModelToken(Customer.name));
  const batcher = app.get(CustomerIndexBatcher);
  const before = await customers.countDocuments();
  const ids = (await customers.find().limit(3).lean()).map((d) => String(d._id));

  const redis = new Redis('redis://127.0.0.1:6379');
  await redis.del('haravan:es:pending');

  console.log('--- nap 3 khach vao bo dem ---');
  for (const id of ids) batcher.enqueue(id);

  await new Promise((r) => setTimeout(r, 300));
  console.log('bo dem sau khi nap:', await redis.hgetall('haravan:es:pending'));
  console.log('co bao gio dung con tro nghieng:', await redis.keys('haravan:es:processing:*'));

  console.log('--- cho het han 3 giay ---');
  await new Promise((r) => setTimeout(r, 4500));
  console.log('bo dem sau khi het han:', await redis.hgetall('haravan:es:pending'));

  const after = await customers.countDocuments();
  console.log(`khach trong Mongo: ${before} -> ${after}`);
  console.log(`con key processing bi bo lai: ${(await redis.keys('haravan:es:processing:*')).length}`);

  await redis.quit();
  await app.close();
}

void main();
