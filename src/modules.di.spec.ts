import { Test } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { MongoModule } from '../mongo/mongo.module';
import { mongoConfig } from '../mongo/mongo.config';
import { appConfig } from './config';
import { ApiModule } from './api/api.module';
import { CustomerModule } from './customer/customer.module';
import { HaravanModule } from './haravan/haravan.module';
import { OrderModule } from './order/order.module';
import { QueueModule } from './queue/queue.module';
import { WebhookPrivateModule } from './webhook-private/webhook-private.module';
import { WebhookAppModule } from './webhook-app/webhook-app.module';

describe('Haravan modules (DI graph)', () => {
  it('resolve DI + ket noi MongoDB', async () => {
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
        WebhookAppModule,
        OrderModule,
        CustomerModule,
        HaravanModule,
      ],
    }).compile();

    const app = ref.createNestApplication();
    await app.init();

    const routes = app
      .getHttpAdapter()
      .getInstance()
      ._router.stack.filter((l: any) => l.route)
      .map(
        (l: any) =>
          `${Object.keys(l.route.methods)[0].toUpperCase()} ${l.route.path}`,
      );
    console.log('\nROUTES:\n' + routes.join('\n'));

    expect(routes).toContain('POST /webhooks/haravan');
    expect(routes).not.toContain('GET /webhooks/haravan');

    expect(routes).toContain('GET /webhooks/app');
    expect(routes).toContain('POST /webhooks/app');

    await app.close();
  }, 60000);
});
