import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { appConfig } from '../config';
import { Shop, ShopSchema } from '../webhook-app/webhook-app.entity';
import { AccessTokenStore } from './access-token.store';
import { ApiClient } from './api.service';

/**
 * Lop goi Omni API (lay don, xac nhan don). Dung fetch co san cua Node.
 *
 * Dang ky `shops` o day vi AccessTokenStore doc access token da luu tu
 * OAuth callback (webhooks/callback).
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
