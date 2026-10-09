import {
  BadRequestException,
  Injectable,
  Logger,
  OnModuleInit,
} from '@nestjs/common';
import {
  Job,
  JobQueue,
  JOB_NAMES,
  NonRetryableError,
} from '../../queue/queue.service';
import { ApiError } from '../../api/api.service';
import { OrderActionsService } from '../services/order-actions.service';
import { OrderService } from '../services/order.service';

/** Nội dung công việc cho mọi thao tác đẩy lên Haravan. */
export interface OrderActionJobPayload {
  orgId: number;
  /** Bỏ trống với `order.create` vì đơn chưa tồn tại trên Haravan. */
  haravanOrderId?: number;
  /** Người thao tác, ghi vào audit log. */
  actor?: string;
  /** Thao tác do người dùng bấm (khác với worker xử lý webhook). */
  manual?: boolean;
  /** Thân request gửi lại đúng như controller nhận từ FE. */
  body?: Record<string, unknown>;
}

/**
 * Worker cho các thao tác đi ra Haravan: tạo, xác nhận, hủy, đóng, mở, cập nhật,
 * hoàn tiền và giao dịch.
 *
 * Controller chỉ đẩy công việc vào hàng đợi rồi trả `202 Accepted` kèm `jobId`.
 * Nhờ đó số lượng request lên Haravan bị giới hạn bởi `HARAVAN_QUEUE_CONCURRENCY`,
 * và người dùng chỉ biết kết quả thật khi Haravan đã trả lời (FE poll trạng thái).
 */
@Injectable()
export class OrderActionWorker implements OnModuleInit {
  private readonly logger = new Logger(OrderActionWorker.name);

  constructor(
    private readonly jobQueue: JobQueue,
    private readonly orders: OrderService,
    private readonly actions: OrderActionsService,
  ) {}

  /**
   * Lỗi 4xx từ Haravan (sai số tiền, sai kind, đơn không tồn tại…) không thử lại
   * được, đóng job ngay để người dùng thấy lỗi sớm. 429 và 5xx vẫn retry.
   */
  private rethrow(error: unknown): never {
    const status = (error as ApiError)?.statusCode;
    if (status && status >= 400 && status < 500 && status !== 429) {
      throw new NonRetryableError((error as Error).message);
    }
    const nestStatus = (error as { getStatus?: () => number })?.getStatus?.();
    if (nestStatus && nestStatus >= 400 && nestStatus < 500) {
      throw new NonRetryableError((error as Error).message);
    }
    throw error;
  }

  onModuleInit(): void {
    this.jobQueue.registerHandler<OrderActionJobPayload>(
      JOB_NAMES.ORDER_CREATE,
      (job) => this.handleCreate(job),
    );
    this.jobQueue.registerHandler<OrderActionJobPayload>(
      JOB_NAMES.ORDER_CONFIRM,
      (job) => this.handleConfirm(job),
    );
    this.jobQueue.registerHandler<OrderActionJobPayload>(
      JOB_NAMES.ORDER_CANCEL,
      (job) => this.handleOrderAction(job, 'cancel'),
    );
    this.jobQueue.registerHandler<OrderActionJobPayload>(
      JOB_NAMES.ORDER_CLOSE,
      (job) => this.handleOrderAction(job, 'close'),
    );
    this.jobQueue.registerHandler<OrderActionJobPayload>(
      JOB_NAMES.ORDER_OPEN,
      (job) => this.handleOrderAction(job, 'open'),
    );
    this.jobQueue.registerHandler<OrderActionJobPayload>(
      JOB_NAMES.ORDER_UPDATE,
      (job) => this.handleOrderAction(job, 'update'),
    );
    this.jobQueue.registerHandler<OrderActionJobPayload>(
      JOB_NAMES.ORDER_REFUND,
      (job) => this.handleOrderAction(job, 'refund'),
    );
    this.jobQueue.registerHandler<OrderActionJobPayload>(
      JOB_NAMES.ORDER_TRANSACTION,
      (job) => this.handleOrderAction(job, 'transaction'),
    );
  }

  /** Tạo đơn trên Haravan rồi lưu bản ghi đơn hàng trả về. */
  private async handleCreate(job: Job<OrderActionJobPayload>): Promise<void> {
    const { orgId, body, actor } = job.payload;
    if (!body) throw new BadRequestException('Thiếu dữ liệu tạo đơn hàng');

    const order = await this.orders
      .createOrder(orgId, body as never)
      .catch((error: unknown) => this.rethrow(error));

    this.logger.log(
      `Đơn ${order.haravanOrderId} (org ${orgId}) đã tạo trên Haravan bởi ${
        actor ?? 'người dùng'
      }`,
    );
    job.result = JSON.stringify({
      message: `Đã tạo đơn ${
        order.orderName ?? order.orderNumber ?? order.haravanOrderId
      }`,
      haravanOrderId: order.haravanOrderId,
    });
  }

  /** Xác nhận đơn thủ công; rule trong service vẫn quyết định bỏ qua hay gửi. */
  private async handleConfirm(job: Job<OrderActionJobPayload>): Promise<void> {
    const { orgId, haravanOrderId, actor, manual, body } = job.payload;
    if (!haravanOrderId) throw new BadRequestException('Thiếu mã đơn hàng');

    const result = await this.orders
      .confirmOrder({
        orgId,
        haravanOrderId,
        manual: manual ?? true,
        actor,
        force: Boolean(body?.['force']),
        source: 'manual',
      })
      .catch((error: unknown) => this.rethrow(error));

    job.result = JSON.stringify(
      result.confirmed
        ? {
            message: `Đã xác nhận đơn ${
              result.order.orderName ??
              result.order.orderNumber ??
              haravanOrderId
            }`,
            haravanOrderId,
            confirmed: true,
          }
        : {
            message: `Đơn chưa được xác nhận: ${result.decision.skipReason}`,
            haravanOrderId,
            confirmed: false,
          },
    );
  }

  /** Hủy, đóng, mở, cập nhật, hoàn tiền và tạo giao dịch đều là một lần gọi Haravan. */
  private async handleOrderAction(
    job: Job<OrderActionJobPayload>,
    action: 'cancel' | 'close' | 'open' | 'update' | 'refund' | 'transaction',
  ): Promise<void> {
    const { orgId, haravanOrderId, actor, body } = job.payload;
    if (!haravanOrderId) throw new BadRequestException('Thiếu mã đơn hàng');
    const input = body ?? {};

    try {
      switch (action) {
        case 'cancel':
          await this.actions.cancelOrder({
            orgId,
            haravanOrderId,
            actor,
            amount: input['amount'] as never,
            email: input['email'] as never,
            reason: input['reason'] as never,
            refund: input['refund'] as never,
            restock: input['restock'] as never,
            note: input['note'] as never,
            ignoreCancelFulfillment: input[
              'ignore_cancel_fulfillment'
            ] as never,
          });
          break;
        case 'close':
          await this.actions.closeOrder({
            orgId,
            haravanOrderId,
            actor,
            note: input['note'] as never,
          });
          break;
        case 'open':
          await this.actions.openOrder({ orgId, haravanOrderId, actor });
          break;
        case 'update':
          await this.actions.updateOrder({
            orgId,
            haravanOrderId,
            actor,
            note: input['note'] as never,
            noteAttributes: input['note_attributes'] as never,
            email: input['email'] as never,
            phone: input['phone'] as never,
          });
          break;
        case 'refund': {
          const transactions =
            (input['transactions'] as Array<Record<string, unknown>>) ?? [];
          const first = transactions[0] ?? {};
          await this.actions.refundOrder({
            orgId,
            haravanOrderId,
            actor,
            amount: (first['amount'] ?? input['amount']) as never,
            gateway: first['gateway'] as never,
            note: (first['note'] ?? input['note']) as never,
          });
          break;
        }
        case 'transaction':
          await this.actions.createTransaction({
            orgId,
            haravanOrderId,
            amount: Number(input['amount'] ?? 0),
            kind: String(input['kind'] ?? 'capture'),
            gateway: input['gateway'] as never,
            note: input['note'] as never,
          });
          break;
      }
    } catch (error) {
      this.rethrow(error);
    }

    this.logger.log(
      `Đơn ${haravanOrderId} (org ${orgId}): ${action} đã xử lý xong`,
    );
    job.result = JSON.stringify({
      message: `Haravan đã xử lý xong thao tác ${action} cho đơn ${haravanOrderId}`,
      haravanOrderId,
    });
  }
}
