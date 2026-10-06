import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { OrderPayload } from '../interface/order.interface';
import { logOrderDecision } from '../core/order-decision-logger';
import { WebhookPrivateStatus } from '../webhook-private/webhook-private.entity';
import { WebhookPrivateService } from '../webhook-private/webhook-private.service';
import { OrderService } from './order.service';
import { Job, JobQueue, JOB_NAMES } from '../queue/queue.service';

export interface OrderCreatedPayload {
  orgId: number;
  haravanOrderId: number;
  webhookEventId?: string;
  topic: string;
}

/**
 * Worker xu ly don hang: doc payload da luu -> len DB -> danh gia rule -> confirm.
 *
 * Job duoc day vao queue boi WebhookController, nen controller luon tra 200
 * trong vong 5 giay nhu Harovan yeu cau, con viec nang chay o day.
 */
@Injectable()
export class OrderWorker implements OnModuleInit {
  private readonly logger = new Logger(OrderWorker.name);

  constructor(
    private readonly jobQueue: JobQueue,
    private readonly orderService: OrderService,
    private readonly webhookService: WebhookPrivateService,
  ) {}

  onModuleInit(): void {
    this.jobQueue.registerHandler<OrderCreatedPayload>(
      JOB_NAMES.ORDER_CREATED,
      (job) => this.handleOrderCreated(job),
    );
  }

  private async handleOrderCreated(
    job: Job<OrderCreatedPayload>,
  ): Promise<void> {
    const { orgId, haravanOrderId, webhookEventId, topic } = job.payload;

    this.logger.log(
      `Xu ly don ${haravanOrderId} (org ${orgId}, topic ${topic}, ` +
        `lan ${job.attempt}/${job.maxAttempts})`,
    );

    try {
      if (webhookEventId) {
        await this.webhookService.markStatus(
          webhookEventId,
          WebhookPrivateStatus.PROCESSING,
          {
            jobId: job.id,
          },
        );
      }

      const payload = await this.loadPayload(
        webhookEventId,
        orgId,
        haravanOrderId,
      );

      const result = await this.orderService.processIncomingOrder({
        orgId,
        payload,
        source: 'webhook',
        jobId: job.id,
      });

      let priorHistory: { priorOrderCount: number; priorSpent: number } | null =
        null;
      const hasCustomerIdentity = Boolean(
        payload.customer?.id ||
          payload.customer?.email?.trim() ||
          payload.customer?.phone?.trim() ||
          payload.email?.trim() ||
          payload.shipping_address?.phone?.trim(),
      );
      if (hasCustomerIdentity) {
        try {
          priorHistory = await this.orderService.countPriorOrders(
            orgId,
            result.order,
          );
        } catch (error) {
          this.logger.warn(
            `Khong dem duoc lich su don ${haravanOrderId}: ${
              (error as Error).message
            }`,
          );
        }
      }

      if (webhookEventId) {
        await this.webhookService.markStatus(
          webhookEventId,
          WebhookPrivateStatus.PROCESSED,
        );
      }

      this.logger.log(
        `Don ${haravanOrderId}: confirmed=${result.confirmed}, ` +
          `prior=${result.decision.priorOrderCount}, ` +
          `reason=${result.decision.skipReason}`,
      );

      // Log de doc: khach cu hay moi, da confirm hay bo qua
      logOrderDecision({
        endpoint: 'POST /api/v1/webhooks/haravan (worker)',
        topic,
        orgId,
        orderId: haravanOrderId,
        orderName: payload.name ?? payload.order_number ?? null,
        totalPrice: payload.total_price ?? null,
        customerName:
          payload.shipping_address?.name ??
          [payload.customer?.first_name, payload.customer?.last_name]
            .filter(Boolean)
            .join(' ') ??
          null,
        customerPhone:
          payload.shipping_address?.phone ?? payload.customer?.phone ?? null,
        customerEmail: payload.customer?.email ?? payload.email ?? null,
        khachCu: result.decision.isReturningCustomer,
        soDonTruoc: priorHistory?.priorOrderCount ?? null,
        chiTieuTruoc: priorHistory?.priorSpent ?? null,
        confirmed: result.confirmed,
        confirmedStatus: payload.confirmed_status ?? null,
        financialStatus: payload.financial_status ?? null,
        skipReason: result.decision.skipReason,
      });
    } catch (error) {
      const message = (error as Error).message;

      logOrderDecision({
        endpoint: 'POST /api/v1/webhooks/haravan (worker)',
        topic,
        orgId,
        orderId: haravanOrderId,
        confirmed: false,
        error: message,
      });

      if (webhookEventId) {
        await this.webhookService.markStatus(
          webhookEventId,
          WebhookPrivateStatus.FAILED,
          {
            error: message,
            jobId: job.id,
          },
        );
      }

      // Nem lai cho queue retry
      this.logger.error(`Xu ly don ${haravanOrderId} that bai: ${message}`);
      throw error;
    }
  }

  /**
   * Lay payload don.
   * Uu tien dung payload da luu trong webhook event (chinh du lieu da verify
   * HMAC, khong goi lai Harovan). Neu khong con -> goi Omni API lay day du.
   */
  private async loadPayload(
    webhookEventId: string | undefined,
    orgId: number,
    haravanOrderId: number,
  ): Promise<OrderPayload> {
    const fromWebhook = webhookEventId
      ? await this.webhookService.extractOrderPayload(
          webhookEventId,
          orgId,
          haravanOrderId,
        )
      : null;

    if (fromWebhook) return fromWebhook as OrderPayload;

    this.logger.warn(
      `Khong tim thay payload da xac thuc cho don ${haravanOrderId}, fallback goi Haravan API`,
    );

    const res = await this.orderService.fetchOrderFromApi(
      orgId,
      haravanOrderId,
    );
    return res;
  }
}
