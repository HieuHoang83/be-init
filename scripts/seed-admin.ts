/**
 * Tao role + user Super Admin de dang nhap lay token cho API.
 *
 * Dung `POST /api/v1/auth/register` truc tiep chua duoc: endpoint do can Role
 * ton tai truoc, ma bang `roles` rong khi moi cai BE.
 *
 *   npm run seed:admin
 *
 * Mac dinh: 0961277630 / 123456. Ghi de qua bien moi truong:
 *   ADMIN_PHONE=... ADMIN_PASSWORD=... ADMIN_NAME=...
 *
 * Khong commit mat khau nay - chi dung o moi truong local/dev.
 */
import { NestFactory } from '@nestjs/core';
import { getModelToken } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { AppModule } from '../src/app.module';
import { AuthService } from '../src/auth/auth.service';
import { Role, RoleDocument } from '../src/user/user.entity';

/** Role he thong - `registerUser` gan role theo ten, ten phai ton tai truoc */
const ROLES = ['Super Admin', 'Assistant Admin', 'Customer'] as const;

const DEFAULT_PHONE = '0961277630';
const DEFAULT_PASSWORD = '123456';
const DEFAULT_NAME = 'Admin';

async function main(): Promise<void> {
  const phone = process.env.ADMIN_PHONE ?? DEFAULT_PHONE;
  const password = process.env.ADMIN_PASSWORD ?? DEFAULT_PASSWORD;
  const name = process.env.ADMIN_NAME ?? DEFAULT_NAME;

  const app = await NestFactory.createApplicationContext(AppModule, {
    logger: ['error', 'warn'],
  });

  try {
    /* ------------------------------------------------ 1) dam bao co Role */

    const roleModel = app.get<Model<RoleDocument>>(getModelToken(Role.name));

    for (const roleName of ROLES) {
      const exists = await roleModel.findOne({ name: roleName }).exec();
      if (!exists) {
        await roleModel.create({ name: roleName });
        console.log(`+ Tao role "${roleName}"`);
      }
    }

    /* ---------------------------------------------------- 2) tao user */

    const authService = app.get(AuthService);

    try {
      const user = await authService.registerUser({
        name,
        phone,
        password,
        role: 'Super Admin',
      });

      console.log(`\n+ Tao user "${name}" / ${phone} / Super Admin`);
      console.log(`  id: ${String((user as { _id: unknown })._id)}`);
    } catch (error) {
      const message = (error as Error).message;

      if (message.includes('already registered')) {
        console.log(`\n= User ${phone} da ton tai - giu nguyen mat khau cu`);
        console.log('  Neu quen mat khau, xoa user roi chay lai script nay.');
      } else {
        throw error;
      }
    }

    /* -------------------------------------------------------- 3) huong dan */

    console.log('\n--- Dang nhap ---');
    console.log(`curl -X POST http://localhost:3000/api/v1/auth/login \\`);
    console.log(`  -H "Content-Type: application/json" \\`);
    console.log(`  -d '{"phone":"${phone}","password":"${password}"}'`);

    console.log('\n--- So luong khach ---');
    console.log('curl "http://localhost:3000/api/v1/customers/stats" \\');
    console.log('  -H "Authorization: Bearer <token>"');

    console.log('\n--- Danh sach don (co cot khach quay lai) ---');
    console.log('curl "http://localhost:3000/api/v1/orders?limit=20" \\');
    console.log('  -H "Authorization: Bearer <token>"');
  } finally {
    await app.close();
  }
}

main().catch((error) => {
  console.error('\nSeed that bai:', (error as Error).message);
  process.exit(1);
});
