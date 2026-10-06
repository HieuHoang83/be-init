/**
 * Tạo vai trò và tài khoản Super Admin để đăng nhập lấy token API.
 *
 * Chưa thể gọi trực tiếp `POST /api/v1/auth/register`: endpoint cần có vai trò
 * trước, nhưng collection `roles` đang trống khi cài BE mới.
 *
 *   npm run seed:admin
 *
 * Mặc định: 0961277630 / 123456. Có thể ghi đè bằng biến môi trường:
 *   ADMIN_PHONE=... ADMIN_PASSWORD=... ADMIN_NAME=...
 *
 * Không commit mật khẩu này; chỉ dùng trong môi trường local/dev.
 */
import { NestFactory } from '@nestjs/core';
import { getModelToken } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { AppModule } from '../src/app.module';
import { AuthService } from '../src/auth/auth.service';
import { Role, RoleDocument } from '../src/user/user.entity';

/** Vai trò hệ thống; `registerUser` tìm theo tên nên vai trò phải tồn tại trước. */
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
    /* ---------------------- 1) Đảm bảo các vai trò đã tồn tại */

    const roleModel = app.get<Model<RoleDocument>>(getModelToken(Role.name));

    for (const roleName of ROLES) {
      const exists = await roleModel.findOne({ name: roleName }).exec();
      if (!exists) {
        await roleModel.create({ name: roleName });
        console.log(`+ Tao role "${roleName}"`);
      }
    }

    /* ---------------------- 2) Tạo tài khoản */

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

    /* ---------------------- 3) Hướng dẫn đăng nhập và gọi API */

    console.log('\n--- Dang nhap ---');
    console.log(`curl -X POST http://localhost:3000/api/v1/auth/login \\`);
    console.log(`  -H "Content-Type: application/json" \\`);
    console.log(`  -d '{"phone":"${phone}","password":"<ADMIN_PASSWORD>"}'`);

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
