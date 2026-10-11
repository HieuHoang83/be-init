import { Global, Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { elasticsearchConfig } from './elasticsearch.config';
import { ElasticsearchService } from './elasticsearch.service';

/**
 * Cung cap `ElasticsearchService` cho toan he thong.
 *
 * Module nay `global` vi nhieu module deu can ghi va doc index khach hang. Khon gam MongoDB
 * hay hang doi, nen no khong gay vong phu thuoc.
 */
@Global()
@Module({
  imports: [ConfigModule.forFeature(elasticsearchConfig)],
  providers: [ElasticsearchService],
  exports: [ElasticsearchService],
})
export class ElasticsearchModule {}
