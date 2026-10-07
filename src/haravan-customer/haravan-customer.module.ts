import { Module } from '@nestjs/common';
import { ApiModule } from '../api/api.module';
import { HaravanCustomerController } from './haravan-customer.controller';
import { HaravanCustomerAddressController } from './haravan-customer-address.controller';
import { HaravanCustomerService } from './haravan-customer.service';

@Module({
  imports: [ApiModule],
  controllers: [HaravanCustomerController, HaravanCustomerAddressController],
  providers: [HaravanCustomerService],
  exports: [HaravanCustomerService],
})
export class HaravanCustomerModule {}
