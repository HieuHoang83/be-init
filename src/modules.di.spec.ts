import { Test } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { MongoModule } from '../mongo/mongo.module';
import { mongoConfig } from '../mongo/mongo.config';
import { appConfig } from './config';
import { ApiModule } from './api/api.module';
import { CustomerModule } from './customer/customer.module';
import { OrderModule } from './order/order.module';
import { QueueModule } from './queue/queue.module';
import { WebhookPrivateModule } from './webhook-private/webhook-private.module';
import { WebhookAppModule } from './webhook-app/webhook-app.module';

/**
 * Smoke test: 4 module don lap phai resolve DI duoc va MongoDB ket noi duoc.
 * Khong dung route thuong cua AppModule de tranh phu thuoc module user/auth.
 */
describe('Haravan modules (DI graph)', () => {
  it('resolve DI + ket noi MongoDB', async () => {
    const ref = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          load: [appConfig, mongoConfig],
          envFilePath: ['.env.local', '.env', 'atlas-credentials.env'],
        }),
        MongoModule,
        QueueModule,
        ApiModule,
        WebhookPrivateModule,
        WebhookAppModule,
        OrderModule,
        CustomerModule,
      ],
    }).compile();

    const app = ref.createNestApplication();
    await app.init();

    const routes = app
      .getHttpAdapter()
      .getInstance()._router.stack.filter((l: any) => l.route)
      .map(
        (l: any) =>
          `${Object.keys(l.route.methods)[0].toUpperCase()} ${l.route.path}`,
      );
    console.log('\nROUTES:\n' + routes.join('\n'));

    // Webhook rieng tu: chi POST (khong co GET challenge)
    expect(routes).toContain('POST /webhooks/haravan');
    expect(routes).not.toContain('GET /webhooks/haravan');

    // Webhook ket noi app: co GET subscribe challenge + POST nhan thong bao
    expect(routes).toContain('GET /webhooks/app');
    expect(routes).toContain('POST /webhooks/app');

    await app.close();
  }, 60000);
});
