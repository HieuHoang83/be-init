/**
 * Nap du lieu khach hang mau, dong bo ca hai ve: Haravan va BE.
 *
 * Thu tu xu ly cho moi khach:
 *
 *   1. Tao hoac sua khach tren Haravan bang chinh API `POST`/`PUT /customers.json`.
 *   2. Lay chinh khach do Haravan tra ve de ghi vao MongoDB.
 *   3. Nap san vao Elasticsearch.
 *
 * Nho vay ma khach (`haravanCustomerId`) la ID that cua Haravan chu khong phai so gia, va hai
 * ve luon giong nhau. Chay lai script nhieu lan khong tao trung: lan sau se tim theo so dien
 * thoai da co san va goi `PUT` de cap nhat.
 *
 *   npm run seed:customers
 *   SEED_CUSTOMER_COUNT=500 npm run seed:customers
 *   npm run seed:customers -- --dry-run
 *   npm run seed:customers -- --mongo-only    # bo qua Haravan
 */
import { NestFactory } from '@nestjs/core';
import { getModelToken } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { AppModule } from '../src/app.module';
import {
  CustomerSyncService,
  HaravanCustomerPayload,
} from '../src/customer/customer-sync.service';
import { CustomerIndexService } from '../src/customer/customer-index.service';
import { ElasticsearchService } from '../src/elasticsearch/elasticsearch.service';
import { HaravanCustomerService } from '../src/haravan-customer/haravan-customer.service';
import { Customer, CustomerDocument } from '../src/order/entities/customer.entity';
import { normalizePhone } from '../src/order/mappers/order.mapper';

const DRY_RUN = process.argv.includes('--dry-run');
const MONGO_ONLY = process.argv.includes('--mongo-only');
const COUNT = Number(process.env.SEED_CUSTOMER_COUNT || 200);
const ORG_ID = Number(
  process.env.SEED_CUSTOMER_ORG_ID || process.env.HARAVAN_ORG_ID || 200001220496,
);
/** Cho nghe giua cac lan goi Haravan de khong cham gioi han tan suat. */
const DELAY_MS = Number(process.env.SEED_DELAY_MS || 250);

/**
 * Khoang so dien thoai sinh ra: `09` + 80000000..80000199.
 *
 * Chon khoang nay de khong trung voi khach dang co (096/097/089...) va de ba so cuoi thay doi
 * theo thu tu, nen dung de kiem tra tim kiem 3 so cuoi co phan biet duoc hay khong.
 */
const PHONE_BASE = 80000000;

const FIRST_NAMES = [
  'Nguyen', 'Tran', 'Le', 'Pham', 'Hoang', 'Phan', 'Vu', 'Dang', 'Bui', 'Do',
  'Ho', 'Ngo', 'Duong', 'Ly', 'Vuong',
];

const LAST_NAMES = [
  'Van An', 'Thi Mai', 'Van Binh', 'Thi Lan', 'Quoc Bao', 'Thi Huong',
  'Minh Duc', 'Thi Trang', 'Hoai Nam', 'Thi Ha', 'Van Cuong', 'Thi Ngoc',
];

const STATES = ['enabled', 'enabled', 'enabled', 'blocked'];

/**
 * Bo sinh so ngau nhien co hat: cung mot `seed` luon cho ra cung mot bo du lieu, nen chay lai
 * script khong lam doi du lieu nao.
 */
function makeRandom(seed: number): () => number {
  let state = seed;
  return () => {
    state = (state * 1664525 + 1013904223) % 4294967296;
    return state / 4294967296;
  };
}

function pick(random: () => number, list: string[]): string {
  return list[Math.floor(random() * list.length)];
}

function buildCustomer(index: number, random: () => number): HaravanCustomerPayload {
  const first = pick(random, FIRST_NAMES);
  const last = pick(random, LAST_NAMES);
  const orders = Math.floor(random() * 12);
  const email = `${first}.${last}.${index}`.toLowerCase().replace(/\s+/g, '');

  return {
    first_name: first,
    last_name: last,
    phone: `09${PHONE_BASE + index}`,
    email: `${email}@example.com`,
    state: pick(random, STATES),
    verified_email: random() > 0.5,
    orders_count: orders,
    total_spent: orders * (50000 + Math.floor(random() * 400000)),
  };
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function main(): Promise<void> {
  if (!Number.isFinite(COUNT) || COUNT <= 0) {
    throw new Error('SEED_CUSTOMER_COUNT phai la so nguyen duong');
  }

  console.log(`Nap ${COUNT} khach hang cho org ${ORG_ID}`);
  console.log(
    MONGO_ONLY
      ? 'Che do MONGO-ONLY: khong goi len Haravan.'
      : 'Se dong bo ca Haravan va MongoDB.',
  );
  if (DRY_RUN) console.log('Che do DRY-RUN: chi hien thi, khong ghi gi.');

  // Tat worker de script khong tranh cong voi tien trinh dang chay tren may.
  process.env.JOB_QUEUE_ENABLED = 'false';

  const app = await NestFactory.createApplicationContext(AppModule, {
    logger: ['error', 'warn'],
  });

  try {
    const sync = app.get(CustomerSyncService);
    const haravan = app.get(HaravanCustomerService);
    const indexService = app.get(CustomerIndexService);
    const es = app.get(ElasticsearchService);
    const customerModel = app.get<Model<CustomerDocument>>(
      getModelToken(Customer.name),
    );

    const random = makeRandom(Number(process.env.SEED_RANDOM_SEED || 20260101));
    let createdOnHaravan = 0;
    let updatedOnHaravan = 0;
    let failed = 0;

    for (let index = 0; index < COUNT; index += 1) {
      const customer = buildCustomer(index, random);
      const phone = normalizePhone(customer.phone);

      if (DRY_RUN) {
        if (index < 5) {
          console.log(
            `  [vi du] ${customer.first_name} ${customer.last_name} ${phone} ` +
              `(3 so cuoi: ${phone?.slice(-3)})`,
          );
        }
        continue;
      }

      try {
        let saved: HaravanCustomerPayload;

        if (MONGO_ONLY) {
          // Bo qua Haravan: id gia chi dung cho moi truong khong co token.
          saved = { ...customer, id: 900000000 + index };
        } else {
          const existing = await customerModel
            .findOne({ orgId: ORG_ID, phone })
            .lean()
            .exec();

          const response = existing?.haravanCustomerId
            ? await haravan.updateCustomer(ORG_ID, existing.haravanCustomerId, customer)
            : await haravan.createCustomer(ORG_ID, customer);

          const body = (response ?? {}) as Record<string, unknown>;
          saved = ((body['customer'] ?? body) as HaravanCustomerPayload) ?? {};

          if (existing?.haravanCustomerId) updatedOnHaravan += 1;
          else createdOnHaravan += 1;

          await sleep(DELAY_MS);
        }

        // Ghi vao MongoDB bang chinh du lieu Haravan vua tra ve.
        await sync.upsertFromHaravan(ORG_ID, saved, 'seed');
      } catch (error) {
        failed += 1;
        console.log(
          `  ! ${customer.first_name} ${customer.last_name} (${phone}): ` +
            `${(error as Error).message}`,
        );
      }

      if ((index + 1) % 25 === 0) {
        console.log(`  ... da xu ly ${index + 1}/${COUNT}`);
      }
    }

    if (DRY_RUN) {
      console.log('Het DRY-RUN. Khong co gi duoc ghi.');
      return;
    }

    console.log('\n--- Ket qua ---');
    if (!MONGO_ONLY) {
      console.log(
        `Haravan: ${createdOnHaravan} khach moi, ${updatedOnHaravan} khach cap nhat`,
      );
    }
    console.log(`Loi: ${failed}`);

    if (!es.isEnabled()) {
      console.log('Elasticsearch dang TAT — chi nap du lieu vao MongoDB.');
      return;
    }

    const result = await indexService.reindexAll(500);
    const indexed = await es.countCustomerIndex();
    console.log(
      `Elasticsearch: quet ${result.scanned} khach, ` +
        `${result.ok ? 'ghi thanh cong' : 'CO KHACH BI LOI'}, index dang co ${indexed}`,
    );

    console.log('\nThu cong tim kiem 3 so cuoi:');
    console.log(`  GET /api/v1/customers/search?orgId=${ORG_ID}&q=000`);
  } finally {
    await app.close();
  }
}

main().catch((error) => {
  console.error('\nSeed khach hang that bai:', (error as Error).message);
  process.exit(1);
});
