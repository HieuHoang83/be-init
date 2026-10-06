import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { InjectConnection } from '@nestjs/mongoose';
import { Connection } from 'mongoose';

/**
 * Dịch vụ quản lý kết nối MongoDB của ứng dụng, tương tự PrismaService cho SQL.
 * Dùng để kiểm tra kết nối và đóng kết nối khi ứng dụng dừng.
 */
@Injectable()
export class MongoService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(MongoService.name);

  constructor(@InjectConnection() private readonly connection: Connection) {}

  async onModuleInit(): Promise<void> {
    await this.connection.asPromise();
    this.logger.log(`MongoDB connected: ${this.connection.name}`);
  }

  async onModuleDestroy(): Promise<void> {
    await this.connection.close();
    this.logger.log('MongoDB disconnected');
  }

  isConnected(): boolean {
    return this.connection.readyState === 1;
  }
}