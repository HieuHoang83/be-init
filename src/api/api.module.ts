import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { appConfig } from '../config';
import { Shop, ShopSchema } from '../webhook-app/webhook-app.entity';
import { AccessTokenStore } from './access-token.store';
import { ApiClient } from './api.service';

/**
 * Cung cấp HTTP client gọi Omni API. Các service proxy theo tài nguyên nằm ở
 * module tương ứng và đều kế thừa `HaravanGateway` ở đây.
 *
 * Đăng ký collection `shops` để AccessTokenStore đọc access token do callback
 * OAuth lưu lại.
 */
@Module({
  imports: [
    ConfigModule.forFeature(appConfig),
    MongooseModule.forFeature([{ name: Shop.name, schema: ShopSchema }]),
  ],
  providers: [ApiClient, AccessTokenStore],
  exports: [ApiClient, AccessTokenStore],
})
export class ApiModule {}
