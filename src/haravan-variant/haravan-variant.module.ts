import { Module } from '@nestjs/common';
import { ApiModule } from '../api/api.module';
import { HaravanProductModule } from '../haravan-product/haravan-product.module';
import { HaravanVariantController } from './haravan-variant.controller';

@Module({
  imports: [ApiModule, HaravanProductModule],
  controllers: [HaravanVariantController],
})
export class HaravanVariantModule {}
