import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { ElasticsearchService } from '../elasticsearch/elasticsearch.service';
import { Customer, CustomerDocument } from '../order/entities/customer.entity';
import { toCustomerIndexDoc } from './customer-search.mapper';

/**
 * Ghi khach tu MongoDB sang Elasticsearch.
 *
 * Luon doc lai document tu MongoDB truoc khi ghi thay vi ghi thang thay doi do luu. Nho do
 * worker khong bao gio ghi ban cu hon ban moi, va mot job bi retry se tu sua duoc trang thai
 * dang lech thay vi lam lech them.
 */
@Injectable()
export class CustomerIndexService {
  private readonly logger = new Logger(CustomerIndexService.name);

  constructor(
    @InjectModel(Customer.name)
    private readonly customerModel: Model<CustomerDocument>,
    private readonly es: ElasticsearchService,
  ) {}

  /**
   * Dong bo mot khach theo id trong Mongo.
   *
   * Neu khach da bi xoa o Mongo, lenh xoa cung duoc gui sang index de hai ben khong lech.
   */
  async syncCustomer(customerId: string): Promise<boolean> {
    const result = await this.syncCustomers([customerId]);
    return result.failed.length === 0;
  }

  /**
   * Dong bo mot lo khach theo id trong Mongo.
   *
   * Day la duong chinh sau khi them `CustomerIndexBatcher`: mot lo chi gay **mot** lan doc
   * MongoDB va **mot** lenh `bulk` (than v moi khach mot lenh), nen 10 khach ve trong cung mot
   * giay van chi ton tai 1 request len Elasticsearch.
   *
   * Van doc lai document tu MongoDB chu khong ghi thay doi do luu giữ:
   * - worker khong ghi ban cu hon ban moi;
   * - mot khach bi sua nhieu lan trong mot lo chi ghi ban moi nhat;
   * - job thu lai tu sua duoc trang thai lech thay vi lam lech them.
   */
  async syncCustomers(
    customerIds: string[],
  ): Promise<{ failed: string[]; deleted: number; indexed: number }> {
    const result = { failed: [] as string[], deleted: 0, indexed: 0 };
    if (!customerIds.length) return result;
    if (!this.es.isEnabled()) return result;

    const customers = await this.customerModel
      .find({ _id: { $in: customerIds } })
      .lean()
      .exec();
    const byId = new Map(customers.map((doc) => [String(doc._id), doc]));

    // Khach khong con trong Mongo thi ban ghi trong index cung phai bi xoa, neu khong hai ben
    // se lech nhau va khach da xoa van hien thi khi tim kiem.
    const removed = customerIds.filter((id) => !byId.has(id));
    if (removed.length && (await this.es.bulkDeleteCustomers(removed))) {
      result.deleted = removed.length;
    } else if (removed.length) {
      result.failed.push(...removed);
    }

    const docs: Array<Record<string, unknown>> = [];
    const ids: string[] = [];
    for (const [id, customer] of byId) {
      docs.push(toCustomerIndexDoc(customer as Customer));
      ids.push(id);
    }

    if (docs.length && (await this.es.bulkIndexCustomers(docs, ids))) {
      result.indexed = docs.length;
    } else if (docs.length) {
      result.failed.push(...ids);
    }

    return result;
  }

  /**
   * Nap lai toan bo khach tu Mongo sang index.
   *
   * Dung sau khi bat Elasticsearch lan dau: nhung khach da co san o Mongo truoc do khong co
   * gi de dong bo, phai nap thu cong mot lan.
   */
  async reindexAll(batchSize = 500): Promise<{ scanned: number; ok: boolean }> {
    if (!this.es.isEnabled()) {
      this.logger.warn('Bo qua reindex vi Elasticsearch dang TAT.');
      return { scanned: 0, ok: false };
    }

    const cursor = this.customerModel.find().lean().cursor();
    let batch: Array<Record<string, unknown>> = [];
    let ids: string[] = [];
    let scanned = 0;
    let failed = 0;

    for await (const doc of cursor) {
      batch.push(toCustomerIndexDoc(doc as Customer));
      ids.push(String(doc._id));
      scanned += 1;

      if (batch.length < batchSize) continue;

      if (!(await this.es.bulkIndexCustomers(batch, ids))) failed += batch.length;
      batch = [];
      ids = [];
    }

    if (batch.length && !(await this.es.bulkIndexCustomers(batch, ids))) {
      failed += batch.length;
    }

    const indexed = await this.es.countCustomerIndex();
    this.logger.log(`Reindex xong ${scanned} khach, index dang co ${indexed}`);
    return { scanned, ok: failed === 0 };
  }
}
