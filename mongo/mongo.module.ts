import { Module } from '@nestjs/common';
import { ConfigModule, ConfigType } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { mongoConfig } from './mongo.config';

/**
 * Lop ket noi MongoDB.
 * Chay song song voi PrismaModule cua module user/auth.
 *
 * Config duoc tu nap bang `ConfigModule.forFeature`, nen MongoModule
 * khong phu thuoc vao thu tu load config cua AppModule.
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
