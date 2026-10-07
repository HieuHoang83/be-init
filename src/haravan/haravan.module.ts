import { Module } from '@nestjs/common';
import { ApiModule } from '../api/api.module';
import { HaravanCustomerController } from './haravan-customer.controller';
import { HaravanProductController } from './haravan-product.controller';
import { HaravanVariantController } from './haravan-variant.controller';
import { HaravanOmniService } from './haravan.service';

@Module({
  imports: [ApiModule],
  controllers: [
    HaravanProductController,
    HaravanVariantController,
    HaravanCustomerController,
  ],
  providers: [HaravanOmniService],
})
export class HaravanModule {}
