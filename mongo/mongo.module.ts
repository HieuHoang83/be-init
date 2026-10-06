import { Module } from '@nestjs/common';
import { ConfigModule, ConfigType } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { mongoConfig } from './mongo.config';

/**
 * Kết nối MongoDB, chạy song song với PrismaModule của user/auth.
 *
 * Tự nạp cấu hình bằng `ConfigModule.forFeature`, không phụ thuộc vào thứ tự
 * nạp cấu hình của AppModule.
 */
@Module({
  imports: [
    ConfigModule.forFeature(mongoConfig),
    MongooseModule.forRootAsync({
      imports: [ConfigModule.forFeature(mongoConfig)],
      inject: [mongoConfig.KEY],
      useFactory: (config: ConfigType<typeof mongoConfig>) => ({
        uri: config.uri,
        ...config.options,
      }),
    }),
  ],
  exports: [MongooseModule],
})
export class MongoModule {}
