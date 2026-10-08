import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { Shop, ShopSchema } from '../webhook-app/webhook-app.entity';
import { ShopSettingsController } from './shop-settings.controller';
import { ShopSettingsService } from './shop-settings.service';

@Module({
  imports: [MongooseModule.forFeature([{ name: Shop.name, schema: ShopSchema }])],
  controllers: [ShopSettingsController],
  providers: [ShopSettingsService],
  exports: [ShopSettingsService],
})
export class ShopSettingsModule {}
