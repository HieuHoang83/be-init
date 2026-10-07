import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { appConfig } from '../config';
import { Shop, ShopSchema } from '../webhook-app/webhook-app.entity';
import { AccessTokenStore } from './access-token.store';
import { ApiClient } from './api.service';
import { HaravanOmniService } from './haravan-omni.service';

/**
 * Cung cấp client gọi Omni API (đơn hàng, sản phẩm, khách hàng).
 *
 * Đăng ký collection `shops` để AccessTokenStore đọc access token do callback
 * OAuth lưu lại.
 */
@Module({
  imports: [
    ConfigModule.forFeature(appConfig),
    MongooseModule.forFeature([{ name: Shop.name, schema: ShopSchema }]),
  ],
  providers: [ApiClient, AccessTokenStore, HaravanOmniService],
  exports: [ApiClient, AccessTokenStore, HaravanOmniService],
})
export class ApiModule {}
