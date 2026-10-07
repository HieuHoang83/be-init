import { Module } from '@nestjs/common';
import { HaravanProductModule } from './haravan-product/haravan-product.module';
import { HaravanVariantModule } from './haravan-variant/haravan-variant.module';
import { HaravanCustomerModule } from './haravan-customer/haravan-customer.module';
import { HaravanLocationModule } from './haravan-location/haravan-location.module';
import { HaravanInventoryModule } from './haravan-inventory/haravan-inventory.module';
import { HaravanCollectionModule } from './haravan-collection/haravan-collection.module';
import { HaravanCollectModule } from './haravan-collect/haravan-collect.module';
import { HaravanGeoModule } from './haravan-geo/haravan-geo.module';

@Module({
  imports: [
    HaravanProductModule,
    HaravanVariantModule,
    HaravanCustomerModule,
    HaravanLocationModule,
    HaravanInventoryModule,
    HaravanCollectionModule,
    HaravanCollectModule,
    HaravanGeoModule,
  ],
})
export class HaravanCoreModule {}
