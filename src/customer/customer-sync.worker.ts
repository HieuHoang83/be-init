import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ElasticsearchService } from '../elasticsearch/elasticsearch.service';
import { Job, JobQueue, JOB_NAMES } from '../queue/queue.service';
import { CustomerIndexService } from './customer-index.service';
import {
  CustomerSyncService,
  HaravanCustomerPayload,
} from './customer-sync.service';
import { TOPICS } from '../interface/order.interface';

export interface CustomerEsSyncPayload {
  /** Id cua document trong collection `customers`. */
  customerId?: string;
  /**
   * Lo id can nap.
   *
   * Job ghi tu `CustomerIndexBatcher` luon mang lo nhieu khach de mot job la mot lan doc MongoDB
   * va mot lenh `bulk`. `customerId` de lai vi job tao truoc khi co gom lo van con nam trong
   * hang doi.
   */
  customerIds?: string[];
  /** Id da bi xoa o MongoDB, can xoa khoi index. */
  deleteIds?: string[];
}

/** Noi dung cong viei xu ly webhook `customers/*` gui ve tu Haravan. */
export interface CustomerWebhookSyncPayload {
  orgId: number;
  topic: string;
  customer?: HaravanCustomerPayload;
}

/**
 * Xu ly cong viei dong bo khach hang sang Elasticsearch.
 *
 * Cong viei duoc day vao hang doi sau khi MongoDB da ghi xong, nen luu don khong bao gio bi
 * chan boi Elasticsearch. Worker lay lai document tu MongoDB truoc khi ghi nen viec thu lai
 * la an toan va tu sua duoc trang thai lech.
 */
@Injectable()
export class CustomerSyncWorker implements OnModuleInit {
  private readonly logger = new Logger(CustomerSyncWorker.name);

  constructor(
    private readonly jobQueue: JobQueue,
    private readonly indexService: CustomerIndexService,
    private readonly es: ElasticsearchService,
    private readonly sync: CustomerSyncService,
  ) {}

  onModuleInit(): void {
    this.jobQueue.registerHandler<CustomerEsSyncPayload>(
      JOB_NAMES.CUSTOMER_ES_SYNC,
      (job: Job<CustomerEsSyncPayload>) => this.handle(job),
    );
    this.jobQueue.registerHandler<CustomerWebhookSyncPayload>(
      JOB_NAMES.CUSTOMER_WEBHOOK_SYNC,
      (job: Job<CustomerWebhookSyncPayload>) => this.handleWebhook(job),
    );
  }

  private async handle(job: Job<CustomerEsSyncPayload>): Promise<void> {
    const { customerId, customerIds, deleteIds } = job.payload;
    const ids = customerIds?.length ? customerIds : customerId ? [customerId] : [];

    const failed: string[] = [];
    let indexed = 0;

    if (ids.length) {
      const result = await this.indexService.syncCustomers(ids);
      indexed = result.indexed + result.deleted;
      failed.push(...result.failed);
    }

    if (deleteIds?.length && !(await this.es.bulkDeleteCustomers(deleteIds))) {
      failed.push(...deleteIds);
    }

    if (failed.length) {
      // Nem loi de worker thu lai theo backoff; khong duoc bo qua vi Elasticsearch dang tam thoi
      // khong phan hoi.
      throw new Error(
        `Ghi ${failed.length}/${ids.length + (deleteIds?.length ?? 0)} khach ` +
          `vao Elasticsearch that bai`,
      );
    }

    if (!ids.length && !deleteIds?.length) {
      this.logger.warn(`Job ${job.id} khong co khach nao de nap index`);
      return;
    }

    this.logger.log(`Da dong bo ${indexed} khach sang Elasticsearch`);
  }

  /**
   * Ghi khach moi / cap nhat khach cu theo xac nhan cua Haravan.
   *
   * Day la duong ghi chuan: job vua tao/sua khach cung chay ham nay, nen du Haravan gui webhook
   * ve thi khong ghi trung ma chi ghi lai mot lan nua.
   */
  private async handleWebhook(
    job: Job<CustomerWebhookSyncPayload>,
  ): Promise<void> {
    const { orgId, topic, customer } = job.payload;

    if (topic === TOPICS.CUSTOMER_DELETE) {
      const removed = await this.sync.removeCustomer(
        orgId,
        Number(customer?.id) || undefined,
      );
      this.logger.log(`Xoa khach ${customer?.id ?? '?'} (org ${orgId})`);
      if (!removed) this.logger.debug('Khach da xoa o Mongo nen khong can xoa index');
      return;
    }

    if (!customer) {
      throw new Error(`Webhook ${topic} khong co du lieu khach`);
    }

    const result = await this.sync.upsertFromHaravan(orgId, customer, topic);
    this.logger.log(
      `Webhook ${topic}: khach ${customer.id} da duoc ` +
        `${result.created ? 'tao moi' : 'cap nhat'} trong MongoDB`,
    );
  }
}
