import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Customer, CustomerDocument } from '../order/entities/customer.entity';
import { normalizePhone } from '../order/mappers/order.mapper';
import { CustomerIndexBatcher } from './customer-index.batcher';

/**
 * Du lieu khach theo dung khu cua Haravan.
 *
 * Cung mot kieu chung cho ca hai duong: response cua job goi Haravan va webhook
 * `customers/*` gui ve deu ra cung mot hinh dang.
 */
export interface HaravanCustomerPayload {
  id?: number | null;
  first_name?: string | null;
  last_name?: string | null;
  name?: string | null;
  email?: string | null;
  phone?: string | null;
  state?: string | null;
  verified_email?: boolean | null;
  orders_count?: number | null;
  total_spent?: number | null;
  [key: string]: unknown;
}

export interface UpsertCustomerResult {
  /** `true` neu vua tao moi trong MongoDB, `false` neu da cap nhat khach da co. */
  created: boolean;
  /** Id trong MongoDB, dung cho viec nap Elasticsearch. */
  customerId?: string;
}

/**
 * Ghi khach vao MongoDB roi day sang Elasticsearch.
 *
 * Day la duong ghi duy nhat cho du lieu lay tu Haravan. Ca hai dau deu quy ve day:
 * - worker sau khi goi `POST`/`PUT /customers.json` nhan duoc customer ngay trong response;
 * - webhook `customers/create|update` gui ve sau khi Haravan da xu ly xong.
 *
 * Hai duong deu dung `upsert` nem khoa theo `haravanCustomerId` nen chay mot lan hay hai
 * lan deu cho cung mot ket qua — khong sinh ban ghi trung.
 */
@Injectable()
export class CustomerSyncService {
  private readonly logger = new Logger(CustomerSyncService.name);

  constructor(
    @InjectModel(Customer.name)
    private readonly customerModel: Model<CustomerDocument>,
    private readonly indexBatcher: CustomerIndexBatcher,
  ) {}

  async upsertFromHaravan(
    orgId: number,
    raw: HaravanCustomerPayload,
    source: string,
  ): Promise<UpsertCustomerResult> {
    const haravanCustomerId = raw.id != null ? Number(raw.id) : undefined;
    const phone = normalizePhone(raw.phone);
    const email = raw.email?.trim().toLowerCase() || undefined;
    const fullName =
      raw.name?.trim() ||
      [raw.first_name, raw.last_name].filter(Boolean).join(' ').trim() ||
      undefined;

    // Khach khong co dinh danh nao thi khong the dinh danh duoc, bo qua thay vi tao ban rong.
    if (!haravanCustomerId && !phone && !email) return { created: false };

    const or: Array<Record<string, unknown>> = [];
    if (haravanCustomerId) or.push({ haravanCustomerId });
    if (phone) or.push({ phone });
    if (email) or.push({ email });

    const patch: Record<string, unknown> = { orgId, lastSeenAt: new Date() };
    if (haravanCustomerId) patch['haravanCustomerId'] = haravanCustomerId;
    if (phone) patch['phone'] = phone;
    if (email) patch['email'] = email;
    if (fullName) patch['fullName'] = fullName;
    if (raw.first_name) patch['firstName'] = raw.first_name;
    if (raw.last_name) patch['lastName'] = raw.last_name;
    if (raw.state) patch['state'] = raw.state;
    if (typeof raw.verified_email === 'boolean') {
      patch['verifiedEmail'] = raw.verified_email;
    }
    if (raw.orders_count != null) {
      patch['haravanOrdersCount'] = Number(raw.orders_count) || 0;
    }
    if (raw.total_spent != null) {
      patch['haravanTotalSpent'] = Number(raw.total_spent) || 0;
    }

    const existing = await this.customerModel.findOne({ orgId, $or: or }).lean();

    if (existing) {
      await this.customerModel
        .updateOne({ _id: existing._id }, { $set: patch })
        .exec();
      this.scheduleIndex(String(existing._id));
      this.logger.log(
        `Cap nhat khach ${haravanCustomerId ?? phone ?? email} (org ${orgId}, ${source})`,
      );
      return { created: false, customerId: String(existing._id) };
    }

    try {
      const created = await this.customerModel.create({
        ...patch,
        firstSeenAt: new Date(),
        haravanOrdersCount: patch['haravanOrdersCount'] ?? 0,
        haravanTotalSpent: patch['haravanTotalSpent'] ?? 0,
        infoSourceTopic: source,
      });
      this.scheduleIndex(String(created._id));
      this.logger.log(
        `Tao moi khach ${fullName ?? phone ?? email} (org ${orgId}, ${source})`,
      );
      return { created: true, customerId: String(created._id) };
    } catch (error) {
      // Job va webhook cung ghi mot khach co the chay cung luc; khoa duy nhat bat loi E11000.
      if ((error as { code?: number })?.code !== 11000) throw error;

      const raced = await this.customerModel.findOne({ orgId, $or: or }).lean();
      if (!raced) {
        this.logger.warn(
          `Bo qua ghi khach do xung dot khoa duy nhat khong tim lai duoc (org ${orgId})`,
        );
        return { created: false };
      }

      await this.customerModel
        .updateOne({ _id: raced._id }, { $set: patch })
        .exec();
      this.scheduleIndex(String(raced._id));
      return { created: false, customerId: String(raced._id) };
    }
  }

  /**
   * Xoa khach khi Haravan gui webhook `customers/delete`.
   *
   * Tra ve `true` neu thuc su xoa duoc ban ghi trong MongoDB; khi do index cung duoc xoa theo.
   */
  async removeCustomer(
    orgId: number,
    haravanCustomerId?: number,
  ): Promise<boolean> {
    const filter = haravanCustomerId
      ? { orgId, haravanCustomerId }
      : { orgId };

    const removed = await this.customerModel.findOneAndDelete(filter).lean();
    if (!removed) return false;

    this.indexBatcher.enqueueDelete(String(removed._id));
    return true;
  }

  /**
   * Gom cong viec nap index cho khach vua ghi.
   *
   * Khong nem loi va khong doi: chi day id vao bo dem roi tra ve ngay. Lo se duoc ghi khi du so
   * khach, hoac khi het thoi gian han — xem `CustomerIndexBatcher`. Ghi Mongo da xong la du
   * so thoi tin chinh, thieu index chi la tam thoi va se tu dung khi co Elasticsearch.
   */
  private scheduleIndex(customerId: string): void {
    this.indexBatcher.enqueue(customerId);
  }
}
