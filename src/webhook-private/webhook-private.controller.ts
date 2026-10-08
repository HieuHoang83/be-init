import {
  Body,
  Controller,
  Headers,
  HttpCode,
  Logger,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { Public } from '../decorators/customize';
import { ORDER_TOPIC_SET } from '../interface/order.interface';
import { extractOrder, readWebhookMeta } from '../core/webhook-payload.util';
import { HmacRequest } from '../core/webhook-hmac.guard';
import { HMAC_HEADER } from '../core/webhook-hmac.util';
import { logWebhookPayload } from '../core/webhook-payload-logger';
import { JobQueue, JOB_NAMES } from '../queue/queue.service';
import { WebhookPrivateHmacGuard } from './webhook-private.guard';
import { WebhookPrivateStatus } from './webhook-private.entity';
import { WebhookPrivateService } from './webhook-private.service';

/** Chỉ xử lý tiếp các chủ đề liên quan đến đơn hàng. */
/** Chỉ lưu các header cần kiểm tra; không lưu secret. */
function pickHeaders(headers: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (typeof value === 'string') out[key] = value;
  }
  return out;
}

/**
 * Webhook riêng tư.
 *
 * Khác với webhook ứng dụng, loại này không cần đăng ký bằng
 * hub.verify_token hoặc hub.challenge. Chủ shop tự cấu hình trong
 * Cấu hình -> Thông báo -> Webhooks và nhập URL HTTPS của ứng dụng.
 * Haravan chỉ gửi yêu cầu POST.
 *
 * Chữ ký dùng `X-Haravan-Hmacsha256` =
 * base64(HMAC_SHA256(raw_body, webhook authentication secret)).
 * Phải trả về 200; mã khác, kể cả 3xx, được xem là thất bại. Haravan thử lại
 * tối đa 19 lần trong 48 giờ và có thể xóa đăng ký sau 19 lần thất bại liên tiếp.
 *
 * Vì vậy controller chỉ kiểm tra, lưu lịch sử, đưa việc vào hàng đợi rồi trả
 * 200 ngay. Các thao tác gọi Omni API được xử lý trong OrderWorker.
 */
@ApiTags('Haravan Webhook')
@Controller('webhooks/haravan')
@Public()
export class WebhookPrivateController {
  private readonly logger = new Logger(WebhookPrivateController.name);

  constructor(
    private readonly webhookService: WebhookPrivateService,
    private readonly jobQueue: JobQueue,
  ) {}

  @Post()
  @HttpCode(200)
  @UseGuards(WebhookPrivateHmacGuard)
  @ApiOperation({
    summary:
      'Nhan webhook rieng tu tu Haravan (orders/create, orders/update, orders/paid)',
  })
  async receive(
    @Body() envelope: Record<string, unknown>,
    @Headers() headers: Record<string, unknown>,
    @Req() req: HmacRequest,
  ): Promise<{ received: true; eventId: string; status: string }> {
    const meta = readWebhookMeta(headers, envelope);
    const topic = meta.topic;

    let orgId: number | null = meta.orgId;
    let haravanOrderId: number | null = meta.orderId;
    let error: string | null = null;

    try {
      const extracted = extractOrder(headers, envelope);
      orgId = extracted.orgId;
      haravanOrderId = extracted.order.id;
    } catch (e) {
      error = (e as Error).message;
    }

    // Payload kiểm tra của Haravan không có đơn thật; chỉ ghi nhận, không xử lý.
    if (meta.isTest) {
      error = 'payload test (X-Haravan-Test), bo qua xu ly don';
    }

    logWebhookPayload({
      kind: 'private',
      method: req.method,
      path: req.originalUrl ?? null,
      stage: 'received',
      topic,
      orgId,
      haravanOrderId,
      status: 200,
      raw: req.rawBody?.toString('utf8') ?? null,
      body: envelope,
      headers: pickHeaders(headers),
      error: error ?? undefined,
    });

    this.logger.debug(`Raw payload: ${JSON.stringify(envelope)}`);

    const event = await this.webhookService.record({
      orgId,
      topic,
      haravanOrderId,
      payload: envelope,
      headers: pickHeaders(headers),
      hmacVerified: true,
      haravanRetryCount: Number(headers['x-haravan-retry'] ?? 0),
      status: error
        ? WebhookPrivateStatus.INVALID
        : WebhookPrivateStatus.RECEIVED,
      error: error ?? undefined,
    });
    const eventId = event._id.toString();

    if (error || orgId === null || haravanOrderId === null) {
      this.logger.warn(`Webhook khong xu ly duoc: ${error}`);
      logWebhookPayload({
        kind: 'private',
        method: req.method,
        path: req.originalUrl ?? null,
        stage: 'processed',
        topic,
        orgId,
        haravanOrderId,
        status: 200,
        result: { eventId, outcome: 'invalid_payload' },
        error: error ?? undefined,
      });
      // Vẫn trả 200 để Haravan không gửi lại liên tục payload lỗi.
      return { received: true, eventId, status: 'invalid_payload' };
    }

    if (!ORDER_TOPIC_SET.has(topic)) {
      await this.webhookService.markStatus(
        eventId,
        WebhookPrivateStatus.IGNORED,
      );
      this.logger.log(`Bo qua topic "${topic}"`);
      logWebhookPayload({
        kind: 'private',
        method: req.method,
        path: req.originalUrl ?? null,
        stage: 'processed',
        topic,
        orgId,
        haravanOrderId,
        status: 200,
        result: { eventId, outcome: 'ignored' },
      });
      return { received: true, eventId, status: 'ignored' };
    }

    const job = await this.jobQueue.enqueue(JOB_NAMES.ORDER_CREATED, {
      orgId,
      haravanOrderId,
      webhookEventId: eventId,
      topic,
    });

    await this.webhookService.markStatus(eventId, WebhookPrivateStatus.QUEUED, {
      jobId: job.id,
    });

    this.logger.log(
      `Da nhan ${topic} don ${haravanOrderId} (org ${orgId}) -> job ${job.id}`,
    );

    logWebhookPayload({
      kind: 'private',
      method: req.method,
      path: req.originalUrl ?? null,
      stage: 'processed',
      topic,
      orgId,
      haravanOrderId,
      status: 200,
      result: {
        eventId,
        outcome: 'queued',
        jobId: job.id,
        jobName: JOB_NAMES.ORDER_CREATED,
      },
    });

    return { received: true, eventId, status: 'queued' };
  }
}
