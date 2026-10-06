import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Customer, CustomerDocument } from '../order/customer.entity';
import { Order, OrderDocument, OrderStatus } from '../order/order.entity';

export interface CustomerStats {
  /** Tong so khach dang co trong he thong */
  total: number;
  /** Khach moi trong 30 ngay qua (theo lan dau thay) */
  newLast30Days: number;
  /** Khach da mua it nhat 2 don */
  returning: number;
  /** Khach moi dung 1 don */
  firstTime: number;
  /** Khach co it nhat 1 don da xac nhan */
  withConfirmedOrders: number;
  /** Doanh so don cua khach da xac nhan */
  confirmedRevenue: number;
  /** Khach chua co so dien thoai - can chay `orders/updated` de bu du */
  missingPhone: number;
  /** Khach chua co ten */
  missingName: number;
  byOrg: { orgId: number; total: number; returning: number }[];
}

export interface CustomerListQuery {
  orgId?: number;
  search?: string;
  page?: number;
  limit?: number;
  /** Loc khach quay lai / khach moi */
  kind?: 'returning' | 'first_time' | 'all';
  sort?: 'newest' | 'lastSeen' | 'spent' | 'orders';
}

/**
 * Doc so lieu khach hang.
 *
 * Customer duoc gom tu moi don webhook (create + updated) nen bang `customers`
 * la nguon dem khach chinh - dem `orders` se dem trung vi mot khach nhieu don.
 */
@Injectable()
export class CustomerService {
  private readonly logger = new Logger(CustomerService.name);

  constructor(
    @InjectModel(Customer.name)
    private readonly customerModel: Model<CustomerDocument>,
    @InjectModel(Order.name) private readonly orderModel: Model<OrderDocument>,
  ) {}

  /**
   * So lieu tong quan. Dung cho dashboard va bao cao dinh ky.
   *
   * `returning` phai noi "da mua >= 2 don": `haravanOrdersCount` da gom ca don
   * hien tai cua khach, nen nguong la 2 chu khong phai 1.
   */
  async getStats(orgId?: number): Promise<CustomerStats> {
    const scope = orgId ? { orgId } : {};

    const [agg, missingPhone, missingName, confirmed] = await Promise.all([
      this.customerModel.aggregate<{
        _id: null;
        total: number;
        returning: number;
        firstTime: number;
      }>([
        { $match: scope },
        {
          $group: {
            _id: null,
            total: { $sum: 1 },
            returning: {
              $sum: { $cond: [{ $gte: ['$haravanOrdersCount', 2] }, 1, 0] },
            },
            firstTime: {
              $sum: { $cond: [{ $lte: ['$haravanOrdersCount', 1] }, 1, 0] },
            },
          },
        },
      ]),

      this.customerModel.countDocuments({
        ...scope,
        phone: { $exists: false },
      }),
      this.customerModel.countDocuments({
        ...scope,
        $or: [{ fullName: { $exists: false } }, { fullName: '' }],
      }),

      this.orderModel.aggregate<{ total: number; count: number }>([
        { $match: { ...scope, status: OrderStatus.CONFIRMED } },
        {
          $group: {
            _id: null,
            total: { $sum: '$totalPrice' },
            count: { $sum: 1 },
          },
        },
      ]),
    ]);

    const row = agg[0];
    const newLast30Days = await this.customerModel.countDocuments({
      ...scope,
      firstSeenAt: { $gte: this.daysAgo(30) },
    });

    return {
      total: row?.total ?? 0,
      newLast30Days,
      returning: row?.returning ?? 0,
      firstTime: row?.firstTime ?? 0,
      withConfirmedOrders: confirmed[0]?.count ?? 0,
      confirmedRevenue: confirmed[0]?.total ?? 0,
      missingPhone,
      missingName,
      byOrg: await this.byOrg(orgId),
    };
  }

  /** Tach theo shop - phuc vu khi mot BE nhieu org. */
  private async byOrg(onlyOrg?: number): Promise<CustomerStats['byOrg']> {
    const rows = await this.customerModel.aggregate<{
      _id: number;
      total: number;
      returning: number;
    }>([
      ...(onlyOrg ? [{ $match: { orgId: onlyOrg } }] : []),
      {
        $group: {
          _id: '$orgId',
          total: { $sum: 1 },
          returning: {
            $sum: { $cond: [{ $gte: ['$haravanOrdersCount', 2] }, 1, 0] },
          },
        },
      },
      { $sort: { total: -1 } },
    ]);

    return rows.map((r) => ({
      orgId: r._id,
      total: r.total,
      returning: r.returning,
    }));
  }

  /** Danh sach khach co phan trang + tim theo ten/sdt. */
  async findAll(query: CustomerListQuery): Promise<{
    items: Record<string, unknown>[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  }> {
    const page = Math.max(query.page ?? 1, 1);
    const limit = Math.min(query.limit ?? 20, 200);

    const filter: Record<string, unknown> = {};
    if (query.orgId) filter['orgId'] = query.orgId;

    if (query.search?.trim()) {
      const raw = query.search.trim();
      // `0961277633` va `84961277633` phai ra cung mot khach
      const digits = raw.replace(/\D/g, '');
      const phoneVariants = [
        raw,
        digits,
        digits.startsWith('84') ? `0${digits.slice(2)}` : digits,
      ].filter(Boolean);

      filter['$or'] = [
        { phone: { $in: phoneVariants } },
        { fullName: { $regex: raw, $options: 'i' } },
        { email: { $regex: raw, $options: 'i' } },
      ];
    }

    if (query.kind === 'returning') {
      filter['haravanOrdersCount'] = { $gte: 2 };
    } else if (query.kind === 'first_time') {
      filter['haravanOrdersCount'] = { $lte: 1 };
    }

    const sortMap: Record<string, Record<string, 1 | -1>> = {
      newest: { createdAt: -1 },
      lastSeen: { lastSeenAt: -1 },
      spent: { haravanTotalSpent: -1 },
      orders: { haravanOrdersCount: -1 },
    };

    const [items, total] = await Promise.all([
      this.customerModel
        .find(filter)
        .sort(sortMap[query.sort ?? 'newest'] ?? sortMap['newest'])
        .skip((page - 1) * limit)
        .limit(limit)
        .lean()
        .exec(),
      this.customerModel.countDocuments(filter),
    ]);

    return {
      items: items as unknown as Record<string, unknown>[],
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
    };
  }

  /**
   * Chi tiet 1 khach + don cua khach do.
   *
   * Tim bang sdt truoc (`normalizePhone` da chuan hoa khi luu), sau do thu
   * `haravanCustomerId` va `email` phong khi du lieu nhieu nguon lech nhau.
   */
  async findOneWithOrders(
    orgId: number,
    key: string,
  ): Promise<{ customer: Customer; orders: Record<string, unknown>[] } | null> {
    const digits = key.replace(/\D/g, '');
    const phoneVariants = [
      key,
      digits,
      digits.startsWith('84') ? `0${digits.slice(2)}` : digits,
    ].filter(Boolean);

    const or: Record<string, unknown>[] = [{ phone: { $in: phoneVariants } }];
    if (/^\d+$/.test(key)) or.push({ haravanCustomerId: Number(key) });
    if (key.includes('@')) or.push({ email: key.toLowerCase() });

    const customer = await this.customerModel
      .findOne({ orgId, $or: or })
      .lean()
      .exec();
    if (!customer) return null;

    const orderOr: Record<string, unknown>[] = [
      { phone: { $in: phoneVariants } },
    ];
    if (customer.haravanCustomerId) {
      orderOr.push({ 'customer.haravanId': customer.haravanCustomerId });
    }
    if (customer.email) orderOr.push({ email: customer.email });

    const orders = await this.orderModel
      .find({ orgId, $or: orderOr })
      .sort({ createdAt: -1 })
      .limit(100)
      .select(
        'haravanOrderId orderNumber orderName customerName phone totalPrice status ' +
          'financialStatus confirmedStatus processing createdAt',
      )
      .lean()
      .exec();

    return {
      customer: customer as unknown as Customer,
      orders: orders as unknown as Record<string, unknown>[],
    };
  }

  private daysAgo(days: number): Date {
    return new Date(Date.now() - days * 86_400_000);
  }
}
