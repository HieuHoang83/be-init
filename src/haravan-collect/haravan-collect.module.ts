import { Module } from '@nestjs/common';
import { ApiModule } from '../api/api.module';
import { HaravanCollectController } from './haravan-collect.controller';
import { HaravanCollectService } from './haravan-collect.service';

@Module({
  imports: [ApiModule],
  controllers: [HaravanCollectController],
  providers: [HaravanCollectService],
  exports: [HaravanCollectService],
})
export class HaravanCollectModule {}
