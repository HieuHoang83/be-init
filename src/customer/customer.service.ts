import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Customer, CustomerDocument } from '../order/entities/customer.entity';
import { Order, OrderDocument, OrderStatus } from '../order/entities/order.entity';

export interface CustomerStats {
  /** Tổng số khách hiện có trong hệ thống. */
  total: number;
  /** Khách lần đầu xuất hiện trong 30 ngày gần nhất. */
  newLast30Days: number;
  /** Khách đã mua ít nhất hai đơn. */
  returning: number;
  /** Khách mới chỉ mua một đơn. */
  firstTime: number;
  /** Khách có ít nhất một đơn đã xác nhận. */
  withConfirmedOrders: number;
  /** Tổng giá trị các đơn đã xác nhận của khách. */
  confirmedRevenue: number;
  /** Khách chưa có số điện thoại; cần nhận webhook `orders/updated` để bổ sung. */
  missingPhone: number;
  /** Khách chưa có tên. */
  missingName: number;
  byOrg: { orgId: number; total: number; returning: number }[];
}

export interface CustomerListQuery {
  orgId?: number;
  search?: string;
  page?: number;
  limit?: number;
  /** Lọc khách cũ hoặc khách mới. */
  kind?: 'returning' | 'first_time' | 'all';
  sort?: 'newest' | 'lastSeen' | 'spent' | 'orders';
}

/**
 * Cung cấp số liệu và danh sách khách hàng.
 *
 * Thông tin khách được tổng hợp từ các webhook tạo và cập nhật đơn. Vì vậy,
 * collection `customers` là nguồn đếm chính; đếm đơn hàng sẽ tính trùng khách.
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
   * Lấy số liệu tổng quan cho bảng điều khiển và báo cáo.
   *
   * Khách cũ là người đã mua ít nhất hai đơn. `haravanOrdersCount` đã gồm
   * đơn hiện tại nên ngưỡng phải là 2, không phải 1.
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

  /** Tách dữ liệu theo shop để hỗ trợ nhiều cửa hàng. */
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

  /** Lấy danh sách khách có phân trang và tìm theo tên hoặc số điện thoại. */
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
      // Hai dạng số điện thoại `0961277633` và `84961277633` phải trỏ đến cùng một khách.
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
   * Lấy thông tin một khách hàng và các đơn của khách đó.
   *
   * Tìm theo số điện thoại đã chuẩn hóa trước, sau đó thử `haravanCustomerId`
   * và email để phòng trường hợp dữ liệu từ các nguồn không đồng nhất.
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
