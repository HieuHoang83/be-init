import { Module } from '@nestjs/common';
import { ApiModule } from '../api/api.module';
import { HaravanGeoController } from './haravan-geo.controller';
import { HaravanGeoService } from './haravan-geo.service';

@Module({
  imports: [ApiModule],
  controllers: [HaravanGeoController],
  providers: [HaravanGeoService],
  exports: [HaravanGeoService],
})
export class HaravanGeoModule {}
