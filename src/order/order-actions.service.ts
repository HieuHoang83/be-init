import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ApiClient } from '../api/api.service';
import { OrderPayload } from '../interface/order.interface';
import { OrderAuditService } from './order-audit.service';
import {
  ActionResult,
  ActionType,
  OrderDocument,
  OrderEventAction,
  OrderStatus,
} from './order.entity';
import { OrderService } from './order.service';

/**
 * Thao tác thủ công trên đơn hàng (hủy, đóng, mở, cập nhật, hoàn tiền, giao dịch).
 * Mỗi thao tác đều ghi lại `order_actions` (kỹ thuật) và `order_events` (nghiệp vụ),
 * rồi đồng bộ lại đơn hàng từ response của Haravan.
 */
@Injectable()
export class OrderActionsService {
  private readonly logger = new Logger(OrderActionsService.name);

  constructor(
    private readonly apiClient: ApiClient,
    private readonly orders: OrderService,
    private readonly audit: OrderAuditService,
  ) {}

  private async requireOrderDocument(
    orgId: number,
    haravanOrderId: number,
  ): Promise<OrderDocument> {
    const order = await this.orders.findOrderById(orgId, haravanOrderId);
    if (!order) {
      throw new NotFoundException(
        `Không tìm thấy đơn ${haravanOrderId} của org ${orgId}`,
      );
    }
    return order;
  }

  /**
   * Hủy đơn trên Haravan. `amount` là số tiền hoàn lại (bỏ trống = hoàn toàn bộ),
   * `refund` chỉ ghi nhận hoàn tiền khi đơn đã capture, `restock` trả lại tồn kho.
   */
  async cancelOrder(params: {
    orgId: number;
    haravanOrderId: number;
    actor?: string;
    amount?: number;
    email?: string;
    reason?: string;
    refund?: boolean;
    restock?: boolean;
    note?: string;
    ignoreCancelFulfillment?: boolean;
  }): Promise<OrderDocument> {
    const { orgId, haravanOrderId, actor } = params;
    const order = await this.requireOrderDocument(orgId, haravanOrderId);

    const requestBody: Record<string, unknown> = {};
    if (params.amount !== undefined) requestBody['amount'] = params.amount;
    if (params.email) requestBody['email'] = params.email;
    if (params.reason) requestBody['reason'] = params.reason;
    if (params.refund !== undefined) requestBody['refund'] = params.refund;
    if (params.restock !== undefined) requestBody['restock'] = params.restock;
    if (params.note) requestBody['note'] = params.note;
    if (params.ignoreCancelFulfillment !== undefined) {
      requestBody['ignore_cancel_fulfillment'] =
        params.ignoreCancelFulfillment;
    }

    await this.audit.logAction(
      orgId,
      haravanOrderId,
      ActionType.CANCEL_SEND,
      ActionResult.SUCCESS,
      { manual: true, actor, message: params.reason ?? params.note },
    );

    const startedAt = Date.now();
    try {
      const res = await this.apiClient.cancelOrder(
        orgId,
        haravanOrderId,
        requestBody,
      );

      const mirrored = await this.orders.mirrorOrderFromApi(
        orgId,
        haravanOrderId,
        res.body,
      );
      const updated = mirrored ?? order;
      if (!mirrored) {
        updated.status = OrderStatus.CANCELLED;
        updated.haravanStatus = 'cancelled';
        updated.cancelledStatus = 'cancelled';
        updated.cancelReason = params.reason ?? updated.cancelReason;
        await updated.save();
      }

      await this.audit.logOrderEvent({
        orgId,
        haravanOrderId,
        action: OrderEventAction.CANCELLED,
        source: 'user',
        actor,
        changedFields: ['status', 'haravanStatus', 'cancelledStatus'],
        description: 'Đã hủy đơn hàng.',
      });

      await this.audit.logAction(
        orgId,
        haravanOrderId,
        ActionType.CANCEL_SUCCESS,
        ActionResult.SUCCESS,
        {
          manual: true,
          actor,
          apiCall: {
            method: 'POST',
            url: `/orders/${haravanOrderId}/cancel.json`,
            requestBody,
            statusCode: res.statusCode,
            responseBody: res.body as Record<string, unknown>,
            durationMs: Date.now() - startedAt,
          },
        },
      );

      this.logger.log(
        `Đã hủy đơn ${haravanOrderId} (org ${orgId}) trên Haravan`,
      );
      return updated;
    } catch (error) {
      const message = (error as Error).message;
      await this.audit.logAction(
        orgId,
        haravanOrderId,
        ActionType.CANCEL_FAILED,
        ActionResult.FAILED,
        {
          manual: true,
          actor,
          message,
          apiCall: {
            method: 'POST',
            url: `/orders/${haravanOrderId}/cancel.json`,
            requestBody,
            durationMs: Date.now() - startedAt,
          },
        },
      );
      this.logger.error(`Hủy đơn ${haravanOrderId} thất bại: ${message}`);
      throw error;
    }
  }

  /** Đóng đơn trên Haravan. */
  async closeOrder(params: {
    orgId: number;
    haravanOrderId: number;
    actor?: string;
    note?: string;
  }): Promise<OrderDocument> {
    const { orgId, haravanOrderId, actor } = params;
    const order = await this.requireOrderDocument(orgId, haravanOrderId);
    const requestBody: Record<string, unknown> = {};
    if (params.note) requestBody['note'] = params.note;

    await this.audit.logAction(
      orgId,
      haravanOrderId,
      ActionType.CLOSE_SEND,
      ActionResult.SUCCESS,
      { manual: true, actor, message: params.note },
    );

    const startedAt = Date.now();
    try {
      const res = await this.apiClient.closeOrder(
        orgId,
        haravanOrderId,
        requestBody,
      );

      const mirrored = await this.orders.mirrorOrderFromApi(
        orgId,
        haravanOrderId,
        res.body,
      );
      const updated = mirrored ?? order;
      if (!mirrored) {
        updated.haravanStatus = 'closed';
        updated.closedStatus = 'closed';
        await updated.save();
      }

      await this.audit.logOrderEvent({
        orgId,
        haravanOrderId,
        action: OrderEventAction.CLOSED,
        source: 'user',
        actor,
        changedFields: ['haravanStatus', 'closedStatus'],
        description: 'Đã đóng đơn hàng trên Haravan.',
      });

      await this.audit.logAction(
        orgId,
        haravanOrderId,
        ActionType.CLOSE_SUCCESS,
        ActionResult.SUCCESS,
        {
          manual: true,
          actor,
          apiCall: {
            method: 'POST',
            url: `/orders/${haravanOrderId}/close.json`,
            requestBody,
            statusCode: res.statusCode,
            responseBody: res.body as Record<string, unknown>,
            durationMs: Date.now() - startedAt,
          },
        },
      );

      this.logger.log(`Đã đóng đơn ${haravanOrderId} (org ${orgId})`);
      return updated;
    } catch (error) {
      const message = (error as Error).message;
      await this.audit.logAction(
        orgId,
        haravanOrderId,
        ActionType.CLOSE_FAILED,
        ActionResult.FAILED,
        {
          manual: true,
          actor,
          message,
          apiCall: {
            method: 'POST',
            url: `/orders/${haravanOrderId}/close.json`,
            requestBody,
            durationMs: Date.now() - startedAt,
          },
        },
      );
      this.logger.error(`Dong don ${haravanOrderId} that bai: ${message}`);
      throw error;
    }
  }

  /** Mở lại đơn đã đóng. */
  async openOrder(params: {
    orgId: number;
    haravanOrderId: number;
    actor?: string;
  }): Promise<OrderDocument> {
    const { orgId, haravanOrderId, actor } = params;
    const order = await this.requireOrderDocument(orgId, haravanOrderId);

    await this.audit.logAction(
      orgId,
      haravanOrderId,
      ActionType.OPEN_SEND,
      ActionResult.SUCCESS,
      { manual: true, actor },
    );

    const startedAt = Date.now();
    try {
      const res = await this.apiClient.openOrder(orgId, haravanOrderId);

      const mirrored = await this.orders.mirrorOrderFromApi(
        orgId,
        haravanOrderId,
        res.body,
      );
      const updated = mirrored ?? order;
      if (!mirrored) {
        updated.haravanStatus = 'open';
        updated.closedStatus = 'unclosed';
        await updated.save();
      }

      await this.audit.logOrderEvent({
        orgId,
        haravanOrderId,
        action: OrderEventAction.OPENED,
        source: 'user',
        actor,
        changedFields: ['haravanStatus', 'closedStatus'],
        description: 'Đã mở lại đơn hàng đã đóng.',
      });

      await this.audit.logAction(
        orgId,
        haravanOrderId,
        ActionType.OPEN_SUCCESS,
        ActionResult.SUCCESS,
        {
          manual: true,
          actor,
          apiCall: {
            method: 'POST',
            url: `/orders/${haravanOrderId}/open.json`,
            statusCode: res.statusCode,
            responseBody: res.body as Record<string, unknown>,
            durationMs: Date.now() - startedAt,
          },
        },
      );

      this.logger.log(`Đã mở lại đơn ${haravanOrderId} (org ${orgId})`);
      return updated;
    } catch (error) {
      const message = (error as Error).message;
      await this.audit.logAction(
        orgId,
        haravanOrderId,
        ActionType.OPEN_FAILED,
        ActionResult.FAILED,
        {
          manual: true,
          actor,
          message,
          apiCall: {
            method: 'POST',
            url: `/orders/${haravanOrderId}/open.json`,
            durationMs: Date.now() - startedAt,
          },
        },
      );
      this.logger.error(`Mo don ${haravanOrderId} that bai: ${message}`);
      throw error;
    }
  }

  /**
   * Cập nhật thông tin đơn. Haravan không cho sửa line_items / số lượng /
   * financial_status nên chỉ gửi các trường an toàn (note, note_attributes,
   * email, phone).
   */
  async updateOrder(params: {
    orgId: number;
    haravanOrderId: number;
    actor?: string;
    note?: string;
    noteAttributes?: { name: string; value: string }[];
    email?: string;
    phone?: string;
  }): Promise<OrderDocument> {
    const { orgId, haravanOrderId, actor } = params;
    const order = await this.requireOrderDocument(orgId, haravanOrderId);

    const requestBody: Record<string, unknown> = {};
    if (params.note !== undefined) requestBody['note'] = params.note;
    if (params.noteAttributes !== undefined) {
      requestBody['note_attributes'] = params.noteAttributes;
    }
    if (params.email !== undefined) requestBody['email'] = params.email;
    if (params.phone !== undefined) requestBody['phone'] = params.phone;

    if (!Object.keys(requestBody).length) {
      throw new BadRequestException('Không có trường nào để cập nhật đơn hàng');
    }

    await this.audit.logAction(
      orgId,
      haravanOrderId,
      ActionType.UPDATE_SEND,
      ActionResult.SUCCESS,
      { manual: true, actor },
    );

    const startedAt = Date.now();
    try {
      const res = await this.apiClient.updateOrder(
        orgId,
        haravanOrderId,
        requestBody,
      );

      const mirrored = await this.orders.mirrorOrderFromApi(
        orgId,
        haravanOrderId,
        res.body,
      );
      const updated = mirrored ?? order;

      await this.audit.logOrderEvent({
        orgId,
        haravanOrderId,
        action: OrderEventAction.UPDATED,
        source: 'user',
        actor,
        changedFields: Object.keys(requestBody),
        description: 'Đã cập nhật thông tin đơn hàng trên Haravan.',
      });

      await this.audit.logAction(
        orgId,
        haravanOrderId,
        ActionType.UPDATE_SUCCESS,
        ActionResult.SUCCESS,
        {
          manual: true,
          actor,
          apiCall: {
            method: 'PUT',
            url: `/orders/${haravanOrderId}.json`,
            requestBody,
            statusCode: res.statusCode,
            responseBody: res.body as Record<string, unknown>,
            durationMs: Date.now() - startedAt,
          },
        },
      );

      this.logger.log(`Đã cập nhật đơn ${haravanOrderId} (org ${orgId})`);
      return updated;
    } catch (error) {
      const message = (error as Error).message;
      await this.audit.logAction(
        orgId,
        haravanOrderId,
        ActionType.UPDATE_FAILED,
        ActionResult.FAILED,
        {
          manual: true,
          actor,
          message,
          apiCall: {
            method: 'PUT',
            url: `/orders/${haravanOrderId}.json`,
            requestBody,
            durationMs: Date.now() - startedAt,
          },
        },
      );
      this.logger.error(`Cap nhat don ${haravanOrderId} that bai: ${message}`);
      throw error;
    }
  }

  /** Hoàn tiền cho đơn đã thanh toán. */
  async refundOrder(params: {
    orgId: number;
    haravanOrderId: number;
    actor?: string;
    amount?: number;
    gateway?: string;
    note?: string;
    parentId?: number;
  }): Promise<OrderDocument> {
    const { orgId, haravanOrderId, actor } = params;
    const order = await this.requireOrderDocument(orgId, haravanOrderId);

    const amount = Number(params.amount);
    if (!Number.isFinite(amount) || amount <= 0) {
      throw new BadRequestException('Cần nhập số tiền hoàn tiền lớn hơn 0');
    }

    const transaction: Record<string, unknown> = { kind: 'refund', amount };
    if (params.gateway) transaction['gateway'] = params.gateway;
    if (params.note) transaction['note'] = params.note;
    if (params.parentId) transaction['parent_id'] = params.parentId;

    const requestBody: Record<string, unknown> = { transactions: [transaction] };
    if (params.note) requestBody['note'] = params.note;

    await this.audit.logAction(
      orgId,
      haravanOrderId,
      ActionType.REFUND_SEND,
      ActionResult.SUCCESS,
      { manual: true, actor, message: params.note },
    );

    const startedAt = Date.now();
    try {
      const res = await this.apiClient.createRefund(
        orgId,
        haravanOrderId,
        requestBody,
      );

      const mirrored = await this.orders.mirrorOrderFromApi(
        orgId,
        haravanOrderId,
        res.body,
      );
      const updated = mirrored ?? order;

      await this.audit.logOrderEvent({
        orgId,
        haravanOrderId,
        action: OrderEventAction.REFUNDED,
        source: 'user',
        actor,
        changedFields: ['financialStatus'],
        description: 'Đã hoàn tiền đơn hàng trên Haravan.',
      });

      await this.audit.logAction(
        orgId,
        haravanOrderId,
        ActionType.REFUND_SUCCESS,
        ActionResult.SUCCESS,
        {
          manual: true,
          actor,
          apiCall: {
            method: 'POST',
            url: `/orders/${haravanOrderId}/refunds.json`,
            requestBody,
            statusCode: res.statusCode,
            responseBody: res.body as Record<string, unknown>,
            durationMs: Date.now() - startedAt,
          },
        },
      );

      this.logger.log(
        `Đã hoàn tiền đơn ${haravanOrderId} (org ${orgId}), số tiền ${amount}`,
      );
      return updated;
    } catch (error) {
      const message = (error as Error).message;
      await this.audit.logAction(
        orgId,
        haravanOrderId,
        ActionType.REFUND_FAILED,
        ActionResult.FAILED,
        {
          manual: true,
          actor,
          message,
          apiCall: {
            method: 'POST',
            url: `/orders/${haravanOrderId}/refunds.json`,
            requestBody,
            durationMs: Date.now() - startedAt,
          },
        },
      );
      this.logger.error(`Hoàn tiền đơn ${haravanOrderId} thất bại: ${message}`);
      throw error;
    }
  }

  /** Danh sách giao dịch hoàn tiền của đơn. */
  async listRefunds(
    orgId: number,
    haravanOrderId: number,
    page = 1,
    limit = 20,
  ): Promise<unknown> {
    const res = await this.apiClient.listRefunds(
      orgId,
      haravanOrderId,
      page,
      limit,
    );
    return res.body;
  }

  /** Chi tiết một giao dịch hoàn tiền. */
  async getRefund(
    orgId: number,
    haravanOrderId: number,
    refundId: number,
  ): Promise<unknown> {
    const res = await this.apiClient.getRefund(orgId, haravanOrderId, refundId);
    return res.body;
  }

  /** Danh sách giao dịch của đơn. */
  async listTransactions(
    orgId: number,
    haravanOrderId: number,
  ): Promise<unknown> {
    const res = await this.apiClient.listTransactions(orgId, haravanOrderId);
    return res.body;
  }

  /** Tạo giao dịch (thanh toán) cho đơn. */
  async createTransaction(params: {
    orgId: number;
    haravanOrderId: number;
    amount: number;
    kind: string;
    gateway?: string;
    parentId?: number;
    note?: string;
  }): Promise<unknown> {
    const { orgId, haravanOrderId, amount, kind } = params;
    const numericAmount = Number(amount);
    if (!Number.isFinite(numericAmount) || numericAmount < 0) {
      throw new BadRequestException('Số tiền giao dịch không hợp lệ');
    }

    const requestBody: Record<string, unknown> = {
      kind,
      amount: numericAmount,
    };
    if (params.gateway) requestBody['gateway'] = params.gateway;
    if (params.parentId) requestBody['parent_id'] = params.parentId;
    if (params.note) requestBody['note'] = params.note;

    await this.audit.logAction(
      orgId,
      haravanOrderId,
      ActionType.REFUND_SEND,
      ActionResult.SUCCESS,
      { manual: true, message: `transaction ${kind} ${numericAmount}` },
    );

    const res = await this.apiClient.createTransaction(
      orgId,
      haravanOrderId,
      requestBody,
    );
    await this.orders.mirrorOrderFromApi(orgId, haravanOrderId, res.body);
    return res.body;
  }
  }

