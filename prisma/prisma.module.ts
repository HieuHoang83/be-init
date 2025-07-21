import { Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

@Module({
  providers: [PrismaService],
  exports: [PrismaService], // Đảm bảo PrismaService được export để dùng ở module khác
})
export class PrismaModule {}
