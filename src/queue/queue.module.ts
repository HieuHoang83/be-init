import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { appConfig } from '../config';
import { JobWorker } from './job.worker';
import { Job, JobSchema } from './job.entity';
import { MongoJobQueue } from './mongo-job-queue.service';
import { JobQueue } from './queue.service';

/** Module hàng đợi công việc dùng MongoDB. */
@Module({
  imports: [
    ConfigModule.forFeature(appConfig),
    MongooseModule.forFeature([{ name: Job.name, schema: JobSchema }]),
  ],
  providers: [{ provide: JobQueue, useClass: MongoJobQueue }, JobWorker],
  exports: [JobQueue, MongooseModule],
})
export class QueueModule {}
