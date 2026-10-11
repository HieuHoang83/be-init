import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { ElasticsearchService } from '../elasticsearch/elasticsearch.service';
import { normalizePhone } from '../order/mappers/order.mapper';
import { Customer, CustomerDocument } from '../order/entities/customer.entity';
import {
  parseCustomerSearch,
  ParsedCustomerSearch,
  toSuffixRegex,
} from './customer-search.mapper';

export interface CustomerSearchInput {
  orgId: number;
  q: string;
  page?: number;
  limit?: number;
  kind?: 'returning' | 'first_time' | 'all';
  sort?: 'newest' | 'lastSeen' | 'spent' | 'orders';
}

export interface CustomerSearchHit {
  id: string;
  orgId: number;
  haravanCustomerId?: number;
  fullName?: string;
  firstName?: string;
  lastName?: string;
  email?: string;
  phone?: string;
  phoneSuffix3?: string;
  state?: string;
  ordersCount: number;
  totalSpent: number;
  lastOrderName?: string;
  firstSeenAt?: string;
  lastSeenAt?: string;
}

export interface CustomerSearchResult {
  items: CustomerSearchHit[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
  /** Che do da phan tich tu chuoi nguoi dung. */
  mode: ParsedCustomerSearch['mode'];
  /** He so da tra loi, giup kiem tra khi moi bat Elasticsearch. */
  engine: 'elasticsearch' | 'mongodb';
  /** Goi y cho nguoi dung khi nhap khong hop le. */
  hint?: string;
}

/**
 * Tim kiem khach hang.
 *
 * Elasticsearch la ha tang duoc uu tien; khi chua bat hoac cluster khong phan hoi, truy van
 * trong MongoDB trai nghiem khong doi doi voi nguoi dung. Hai nhanh dung chung mot bo phan tich
 * `parseCustomerSearch` nen cho ra cung mot ket qua, chi khac nguon du lieu.
 */
@Injectable()
export class CustomerSearchService {
  private readonly logger = new Logger(CustomerSearchService.name);

  constructor(
    @InjectModel(Customer.name)
    private readonly customerModel: Model<CustomerDocument>,
    private readonly es: ElasticsearchService,
  ) {}

  async search(input: CustomerSearchInput): Promise<CustomerSearchResult> {
    const parsed = parseCustomerSearch(input.q);
    const page = Math.max(input.page ?? 1, 1);
    const limit = Math.min(input.limit ?? 20, 100);

    if (parsed.mode === 'invalid') {
      return {
        items: [],
        total: 0,
        page,
        limit,
        totalPages: 0,
        mode: parsed.mode,
        engine: 'mongodb',
        hint: parsed.reason,
      };
    }

    const fromEs = await this.searchElasticsearch(parsed, input, page, limit);
    if (fromEs) return { ...fromEs, mode: parsed.mode };

    return {
      ...(await this.searchMongo(parsed, input, page, limit)),
      mode: parsed.mode,
    };
  }

  /* ------------------------------- Elasticsearch */

  private async searchElasticsearch(
    parsed: ParsedCustomerSearch,
    input: CustomerSearchInput,
    page: number,
    limit: number,
  ): Promise<Omit<CustomerSearchResult, 'mode'> | null> {
    const filters: Array<Record<string, unknown>> = [
      { term: { orgId: input.orgId } },
    ];

    const kindFilter = this.buildKindFilter(input.kind);
    if (kindFilter) filters.push(kindFilter);

    let must: Array<Record<string, unknown>> = [];

    if (parsed.mode === 'phone_suffix') {
      // `terms` tren truong keyword: khop dung cac so dien thoai KET THUC bang gia tri da nhap.
      must.push({ terms: { phoneSuffix3: parsed.values } });
    } else if (parsed.mode === 'phone_prefix') {
      must.push({
        bool: {
          should: [
            { term: { phone: normalizePhone(parsed.value) ?? parsed.value } },
            { match: { phonePrefix: parsed.value } },
          ],
          minimum_should_match: 1,
        },
      });
    } else if (parsed.mode === 'text') {
      must.push({
        multi_match: {
          query: parsed.value,
          // Khong dua `phone` vao day: no la `keyword` nen khong ho tro `fuzziness`; nhap so
          // dien thoai da duoc xu ly o cac nhanh `phone_suffix` / `phone_prefix` roi.
          fields: ['fullName^3', 'firstName^2', 'lastName^2', 'email.text'],
          fuzziness: 'AUTO',
        },
      });
    }

    const query: Record<string, unknown> = must.length
      ? { bool: { must, filter: filters } }
      : { bool: { filter: filters } };

    const result = await this.es.searchCustomerIndex<Record<string, unknown>>({
      query,
      from: (page - 1) * limit,
      size: limit,
      sort: this.buildElasticSort(input.sort),
      track_total_hits: true,
    });

    if (!result) return null;

    return {
      items: result.hits.map((hit) => this.toHit(hit)),
      total: result.total,
      page,
      limit,
      totalPages: Math.ceil(result.total / limit) || 1,
      engine: 'elasticsearch',
    };
  }

  /* ------------------------------- MongoDB */

  private async searchMongo(
    parsed: ParsedCustomerSearch,
    input: CustomerSearchInput,
    page: number,
    limit: number,
  ): Promise<Omit<CustomerSearchResult, 'mode'>> {
    const filter: Record<string, unknown> = { orgId: input.orgId };

    if (parsed.mode === 'phone_suffix') {
      // Regex co dau `$` nen chi khop so dien thoai ket thuc bang gia tri da nhap.
      filter['phone'] = { $regex: toSuffixRegex(parsed.values) };
    } else if (parsed.mode === 'phone_prefix') {
      const normalized = normalizePhone(parsed.value);
      const digits = parsed.value.replace(/\D/g, '');
      filter['$or'] = [
        { phone: normalized ?? parsed.value },
        digits ? { phone: { $regex: `^${digits}` } } : null,
      ].filter(Boolean) as Array<Record<string, unknown>>;
    } else if (parsed.mode === 'text') {
      filter['$or'] = [
        { fullName: { $regex: parsed.value, $options: 'i' } },
        { email: { $regex: parsed.value, $options: 'i' } },
        { phone: { $regex: parsed.value.replace(/\D/g, '') || parsed.value, $options: 'i' } },
      ];
    }

    if (input.kind === 'returning') {
      filter['haravanOrdersCount'] = { $gte: 2 };
    } else if (input.kind === 'first_time') {
      filter['haravanOrdersCount'] = { $lte: 1 };
    }

    const sortMap: Record<string, Record<string, 1 | -1>> = {
      newest: { createdAt: -1 },
      lastSeen: { lastSeenAt: -1 },
      spent: { haravanTotalSpent: -1 },
      orders: { haravanOrdersCount: -1 },
    };

    const [docs, total] = await Promise.all([
      this.customerModel
        .find(filter)
        .sort(sortMap[input.sort ?? 'spent'] ?? sortMap['spent'])
        .skip((page - 1) * limit)
        .limit(limit)
        .lean()
        .exec(),
      this.customerModel.countDocuments(filter),
    ]);

    return {
      items: docs.map((doc) => this.toHit(doc as Record<string, unknown>)),
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
      engine: 'mongodb',
    };
  }

  /* ------------------------------- tien ich */

  private buildKindFilter(kind?: string): Record<string, unknown> | null {
    if (kind === 'returning') return { range: { haravanOrdersCount: { gte: 2 } } };
    if (kind === 'first_time') {
      return { range: { haravanOrdersCount: { lte: 1 } } };
    }
    return null;
  }

  private buildElasticSort(sort?: string): Array<Record<string, unknown>> {
    const map: Record<string, Record<string, unknown>> = {
      newest: { createdAt: 'desc' },
      lastSeen: { lastSeenAt: 'desc' },
      spent: { haravanTotalSpent: 'desc' },
      orders: { haravanOrdersCount: 'desc' },
    };
    const primary = map[sort ?? 'spent'] ?? map['spent'];
    // Khong sort theo `_id`: Elasticsearch mac dinh tat fielddata cho truong nay nen se tra
    // `search_phase_execution_exception`. Truong `id` (keyword) dung lam khoa phu de cac trang
    // co ket qua bang nhau van co thu tu on dinh.
    return [primary, { id: 'asc' }];
  }

  /** Chuan hoa document cua ca hai he ve mot hinh dang tra ve chung. */
  private toHit(doc: Record<string, unknown>): CustomerSearchHit {
    return {
      id: String(doc['id'] ?? doc['_id'] ?? ''),
      orgId: Number(doc['orgId'] ?? 0),
      haravanCustomerId: doc['haravanCustomerId'] as number,
      fullName: doc['fullName'] as string,
      firstName: doc['firstName'] as string,
      lastName: doc['lastName'] as string,
      email: doc['email'] as string,
      phone: doc['phone'] as string,
      phoneSuffix3: doc['phoneSuffix3'] as string,
      state: doc['state'] as string,
      ordersCount: Number(doc['haravanOrdersCount'] ?? 0),
      totalSpent: Number(doc['haravanTotalSpent'] ?? 0),
      lastOrderName: doc['lastOrderName'] as string,
      firstSeenAt: toIso(doc['firstSeenAt']),
      lastSeenAt: toIso(doc['lastSeenAt']),
    };
  }
}

function toIso(value: unknown): string | undefined {
  if (!value) return undefined;
  const date = value instanceof Date ? value : new Date(String(value));
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}
