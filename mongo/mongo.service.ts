import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { InjectConnection } from '@nestjs/mongoose';
import { Connection } from 'mongoose';

/**
 * Lop truy cap MongoDB duy nhat cua app (doi chieu PrismaService cho SQL).
 * Dung cho viec kiem tra ket noi / dong ket noi gon khi shutdown.
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