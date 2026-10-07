import { Module } from '@nestjs/common';
import { ApiModule } from '../api/api.module';
import { HaravanLocationController } from './haravan-location.controller';
import { HaravanLocationService } from './haravan-location.service';

@Module({
  imports: [ApiModule],
  controllers: [HaravanLocationController],
  providers: [HaravanLocationService],
  exports: [HaravanLocationService],
})
export class HaravanLocationModule {}
