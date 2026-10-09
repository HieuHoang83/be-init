import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { hasRealCustomerIdentity } from './customer-identity.util';
import {
  Order,
  OrderDocument,
  OrderEventDocument,
  OrderStatus,
} from './order.entity';
import { OrderAuditService } from './order-audit.service';
import { OrderService } from './order.service';

/**
 * Đọc đơn hàng: danh sách, thống kê và nhật ký.
 * Tách riêng khỏi `OrderService` để phần ghi/upsert và phần truy vấn
 * không phụ thuộc lẫn nhau.
 */
@Injectable()
export class OrderQueryService {
  constructor(
    @InjectModel(Order.name) private readonly orderModel: Model<OrderDocument>,
    private readonly audit: OrderAuditService,
    private readonly orders: OrderService,
  ) {}

  async findOrderById(
    orgId: number,
    haravanOrderId: number,
  ): Promise<OrderDocument | null> {
    return this.orderModel.findOne({ orgId, haravanOrderId }).exec();
  }

  async findActions(
    orgId: number,
    haravanOrderId: number,
    limit = 100,
  ): Promise<unknown[]> {
    return this.audit.findActions(orgId, haravanOrderId, limit);
  }

  async findEvents(
    orgId: number,
    haravanOrderId: number,
    limit = 100,
  ): Promise<OrderEventDocument[]> {
    return this.audit.findEvents(orgId, haravanOrderId, limit);
  }

  async findOrders(
    filter: Record<string, unknown>,
    page = 1,
    limit = 20,
  ): Promise<{ items: unknown[]; total: number; page: number; limit: number }> {
    const skip = (Math.max(page, 1) - 1) * limit;

    const [items, total] = await Promise.all([
      this.orderModel
        .find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Math.min(limit, 100))
        .exec(),
      this.orderModel.countDocuments(filter).exec(),
    ]);

    const rows = await this.attachCustomerHistory(items);

    return { items: rows, total, page, limit };
  }

  /** Bổ sung tên đơn và lịch sử mua của khách vào danh sách. */
  private async attachCustomerHistory(
    items: OrderDocument[],
  ): Promise<unknown[]> {
    if (!items.length) return [];

    return Promise.all(
      items.map(async (order) => {
        const doc = order.toObject() as unknown as Record<string, unknown>;
        const processing = (doc['processing'] ?? {}) as Record<string, unknown>;
        const hasCustomerIdentity = hasRealCustomerIdentity({
          haravanId: order.customer?.haravanId,
          email: order.customer?.email ?? order.email,
          phone: order.customer?.phone ?? order.phone,
          fullName: order.customer?.fullName ?? order.customerName,
        });
        const name =
          order.orderName ?? order.orderNumber ?? String(order.haravanOrderId);
        const payloadOrderNumber = Number(order.customer?.ordersCount);

        if (typeof processing['isReturningCustomer'] === 'boolean') {
          const priorOrderCount = Number(processing['priorOrderCount'] ?? 0);
          return {
            ...doc,
            name,
            isReturningCustomer: processing['isReturningCustomer'],
            priorOrderCount,
            priorSpent: processing['priorSpent'] ?? 0,
            customerOrderNumber: !hasCustomerIdentity
              ? null
              : Number.isInteger(payloadOrderNumber) && payloadOrderNumber > 0
              ? payloadOrderNumber
              : priorOrderCount + 1,
          };
        }

        const { priorOrderCount } = await this.orders.countPriorOrders(
          order.orgId,
          order,
        );
        const isReturning = priorOrderCount > 0;

        return {
          ...doc,
          name,
          isReturningCustomer: isReturning,
          priorOrderCount,
          priorSpent: processing['priorSpent'] ?? 0,
          customerOrderNumber: !hasCustomerIdentity
            ? null
            : Number.isInteger(payloadOrderNumber) && payloadOrderNumber > 0
            ? payloadOrderNumber
            : priorOrderCount + 1,
        };
      }),
    );
  }

  async getStats(orgId?: number): Promise<Record<string, unknown>> {
    const match = orgId ? { orgId } : {};

    const [byStatus] = await this.orderModel.aggregate([
      { $match: match },
      { $group: { _id: '$status', count: { $sum: 1 } } },
    ]);

    const [totals] = await this.orderModel.aggregate([
      { $match: match },
      {
        $group: {
          _id: null,
          totalOrders: { $sum: 1 },
          totalRevenue: { $sum: '$totalPrice' },
          confirmedRevenue: {
            $sum: {
              $cond: [
                { $eq: ['$status', OrderStatus.CONFIRMED] },
                '$totalPrice',
                0,
              ],
            },
          },
        },
      },
    ]);

    return {
      byStatus: byStatus ?? {},
      totalOrders: totals?.totalOrders ?? 0,
      totalRevenue: totals?.totalRevenue ?? 0,
      confirmedRevenue: totals?.confirmedRevenue ?? 0,
    };
  }
}

