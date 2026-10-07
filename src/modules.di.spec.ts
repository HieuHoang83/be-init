import { Test } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { MongoModule } from '../mongo/mongo.module';
import { mongoConfig } from '../mongo/mongo.config';
import { appConfig } from './config';
import { ApiModule } from './api/api.module';
import { CustomerModule } from './customer/customer.module';
import { HaravanCoreModule } from './haravan-core.module';
import { DiscountModule } from './discount/discount.module';
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
        HaravanCoreModule,
        DiscountModule,
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

    expect(routes).toContain('GET /haravan/:orgId/discounts');
    expect(routes).toContain('POST /haravan/:orgId/discounts');
    expect(routes).toContain('GET /haravan/:orgId/discounts/:discountId');
    expect(routes).toContain(
      'PUT /haravan/:orgId/discounts/:discountId/enable',
    );
    expect(routes).toContain(
      'PUT /haravan/:orgId/discounts/:discountId/disable',
    );
    expect(routes).toContain('DELETE /haravan/:orgId/discounts/:discountId');

    await app.close();
  }, 60000);
});
