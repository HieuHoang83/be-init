import { Module } from '@nestjs/common';
import { ApiModule } from '../api/api.module';
import { HaravanVariantController } from './haravan-variant.controller';
import { HaravanVariantService } from './haravan-variant.service';

@Module({
  imports: [ApiModule],
  controllers: [HaravanVariantController],
  providers: [HaravanVariantService],
  exports: [HaravanVariantService],
})
export class HaravanVariantModule {}
