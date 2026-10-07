import { Module } from '@nestjs/common';
import { ApiModule } from '../api/api.module';
import { HaravanCollectionController } from './haravan-collection.controller';
import { HaravanCollectionService } from './haravan-collection.service';

@Module({
  imports: [ApiModule],
  controllers: [HaravanCollectionController],
  providers: [HaravanCollectionService],
  exports: [HaravanCollectionService],
})
export class HaravanCollectionModule {}
