import { Module } from '@nestjs/common';
import { ApiModule } from '../api/api.module';
import { HaravanProductController } from './haravan-product.controller';
import { HaravanProductService } from './haravan-product.service';

@Module({
  imports: [ApiModule],
  controllers: [HaravanProductController],
  providers: [HaravanProductService],
  exports: [HaravanProductService],
})
export class HaravanProductModule {}
