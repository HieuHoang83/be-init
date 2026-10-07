import { Module } from '@nestjs/common';
import { ApiModule } from '../api/api.module';
import { HaravanInventoryController } from './haravan-inventory.controller';
import { HaravanInventoryService } from './haravan-inventory.service';

@Module({
  imports: [ApiModule],
  controllers: [HaravanInventoryController],
  providers: [HaravanInventoryService],
  exports: [HaravanInventoryService],
})
export class HaravanInventoryModule {}
