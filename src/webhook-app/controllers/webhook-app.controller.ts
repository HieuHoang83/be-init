import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  Logger,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import { Response } from 'express';
import { Public } from '../../decorators/customize';
import {
  extractOrder,
  extractOrgId,
  readWebhookMeta,
} from '../../core/webhook-payload.util';
import { ORDER_TOPIC_SET } from '../../interface/order.interface';
import { HmacRequest } from '../../core/webhook-hmac.guard';
import { HMAC_HEADER } from '../../core/webhook-hmac.util';
import { logWebhookPayload } from '../../core/webhook-payload-logger';
import { OrderService } from '../../order/services/order.service';
import { JobQueue, JOB_NAMES } from '../../queue/queue.service';
import { WebhookPrivateStatus } from '../../webhook-private/webhook-private.entity';
import { WebhookPrivateService } from '../../webhook-private/webhook-private.service';
import { WebhookAppHmacGuard } from '../guards/webhook-app.guard';
import { WebhookAppService } from '../services/webhook-app.service';

/** Chỉ giữ lại các header cần cho việc kiểm tra. */
function pickHeaders(headers: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (typeof value === 'string') out[key] = value;
  }
  return out;
}

/**
 * Nhận webhook của ứng dụng. Ứng dụng xác thực webhook qua bước GET subscribe,
 * sau đó gửi thông báo bằng POST. Mã xác thực HMAC được lấy từ
 * `app_installations`, không phải secret trong trang Thông báo.
 */
@ApiTags('Haravan Webhook (App)')
@Controller('webhooks/app')
@Public()
export class WebhookAppController {
  private readonly logger = new Logger(WebhookAppController.name);

  constructor(
    private readonly appService: WebhookAppService,
    private readonly orderService: OrderService,
    private readonly jobQueue: JobQueue,
    private readonly webhookService: WebhookPrivateService,
  ) {}

  /** Xác thực đăng ký và trả nguyên giá trị `hub.challenge`. */
  @Get()
  @ApiOperation({ summary: 'App webhook subscribe (hub.challenge)' })
  @ApiQuery({ name: 'hub.verify_token', required: true, type: String })
  @ApiQuery({ name: 'hub.challenge', required: true, type: String })
  async subscribe(
    @Query('hub.mode') mode: string,
    @Query('hub.verify_token') verifyToken: string,
    @Query('hub.challenge') challenge: string,
    @Query('org_id') orgIdQuery: string,
    @Req() req: HmacRequest,
    @Res() res: Response,
  ): Promise<void> {
    if (!verifyToken || !challenge) {
      this.logger.warn('Đăng ký thiếu hub.verify_token hoặc hub.challenge');
      throw new BadRequestException(
        'Thiếu hub.verify_token hoặc hub.challenge',
      );
    }

    const orgId = extractOrgId(req.headers, { org_id: orgIdQuery });

    const ok = await this.appService.verifySubscriptionToken(
      orgId,
      verifyToken,
    );

    // Ghi kết quả xác thực nhưng không ghi giá trị token.
    logWebhookPayload({
      kind: 'app',
      flow: 'verify_token',
      method: req.method,
      path: req.originalUrl ?? null,
      orgId,
      status: ok ? 200 : 401,
      headers: {
        'x-haravan-org-id': String(orgId ?? ''),
        haravan_hub_mode: mode ?? '',
        haravan_hub_verify_token: verifyToken,
        haravan_hub_challenge: challenge,
      },
      result: {
        outcome: ok ? 'verify_token_khop' : 'verify_token_khong_khop',
        // Chỉ ghi độ dài token để đối chiếu, không ghi giá trị token.
        verifyTokenLength: verifyToken.length,
        challengeLength: challenge.length,
      },
      error: ok ? undefined : 'verify_token khong khop',
    });

    if (!ok) {
      this.logger.warn('Mã xác thực không khớp, trả về 401');
      throw new UnauthorizedException('Mã xác thực không hợp lệ');
    }

    if (orgId) {
      await this.appService.beginSubscription({ orgId, verifyToken });
      await this.appService.confirmSubscription(orgId);
    }

    this.logger.log(`Đăng ký webhook thành công (mode=${mode ?? 'subscribe'})`);
    res.status(200).type('text/plain').send(String(challenge));
  }

  /**
   * Nhận thông báo và đưa vào hàng đợi để trả lời Haravan trong thời hạn yêu cầu.
   * Worker sẽ xử lý và lưu đơn hàng sau đó.
   */
  @Post()
  @HttpCode(200)
  @UseGuards(WebhookAppHmacGuard)
  @ApiOperation({ summary: 'Nhận thông báo từ app webhook' })
  async receive(
    @Body() envelope: Record<string, unknown>,
    @Headers() headers: Record<string, unknown>,
    @Req() req: HmacRequest,
  ): Promise<{
    received: true;
    topic: string;
    orgId: number | null;
    queued?: boolean;
    jobId?: string;
  }> {
    const meta = readWebhookMeta(headers, envelope);
    const topic = meta.topic;
    const orgId = meta.orgId;
    const picked = pickHeaders(headers);

    // Payload kiểm tra của Haravan không phải đơn hàng thật.
    if (meta.isTest) {
      this.logger.log(`Bo qua payload test cho topic ${topic}`);
      logWebhookPayload({
        kind: 'app',
        flow: 'event_notification',
        method: req.method,
        path: req.originalUrl ?? null,
        stage: 'processed',
        topic,
        orgId,
        status: 200,
        result: {
          outcome: 'bo_qua_payload_test',
          note: 'X-Haravan-Test: khong phai don hang that',
          headers: picked,
        },
      });
      return { received: true, topic, orgId, queued: false };
    }

    // Chỉ xử lý chủ đề đơn hàng. Các topic khác (customers/*, shop/*) có
    // trường `id` riêng nên tuyệt đối không được coi là đơn hàng.
    if (!ORDER_TOPIC_SET.has(topic)) {
      this.logger.log(`Bo qua topic "${topic}" kiem tra don hang`);
      logWebhookPayload({
        kind: 'app',
        flow: 'event_notification',
        method: req.method,
        path: req.originalUrl ?? null,
        stage: 'processed',
        topic,
        orgId,
        status: 200,
        result: {
          outcome: 'bo_qua_topic_khong_lien_quan',
          note: `Topic ${topic} khong phai su kien don hang`,
          headers: picked,
        },
      });
      return { received: true, topic, orgId, queued: false };
    }

    // Hỗ trợ body dạng order trực tiếp, { data } hoặc { data: { order } }.
    let parsed: ReturnType<typeof extractOrder>;
    try {
      parsed = extractOrder(headers, envelope);
    } catch (extractError) {
      const message = (extractError as Error).message;
      this.logger.warn(`Bo qua app webhook: ${message}`);
      logWebhookPayload({
        kind: 'app',
        flow: 'event_notification',
        method: req.method,
        path: req.originalUrl ?? null,
        stage: 'processed',
        topic,
        orgId,
        status: 200,
        result: { outcome: 'payload_khong_hop_le', note: message, headers: picked },
      });
      return { received: true, topic, orgId, queued: false };
    }
    const order = parsed.order as unknown as Record<string, unknown> | null;
    const haravanOrderId = Number(order?.id);

    // Vẫn trả 200 khi thiếu dữ liệu để Haravan không gửi lại liên tục.
    if (!orgId || !haravanOrderId) {
      this.logger.warn(
        `Bỏ qua app webhook: thiếu orgId hoặc mã đơn (topic ${topic}, org ${
          orgId ?? 'n/a'
        })`,
      );
      logWebhookPayload({
        kind: 'app',
        flow: 'event_notification',
        method: req.method,
        path: req.originalUrl ?? null,
        stage: 'processed',
        topic,
        orgId,
        status: 200,
        result: {
          outcome: 'bo_qua_thieu_du_lieu',
          note: 'Thiếu orgId hoặc order.id; vẫn trả 200 để Haravan không gửi lại',
          headers: picked,
        },
      });
      return { received: true, topic, orgId };
    }

    // Job chỉ chứa mã đơn; payload được lưu riêng để tránh làm phình bảng jobs.
    let jobId: string | undefined;
    try {
      // Lưu payload để worker tải lại. Bảng webhook này dùng chung cho các loại webhook.
      const event = await this.webhookService.record({
        orgId,
        topic,
        haravanOrderId,
        payload: envelope,
        headers: picked,
        status: WebhookPrivateStatus.QUEUED,
      });

      const job = await this.jobQueue.enqueue(JOB_NAMES.ORDER_CREATED, {
        orgId,
        haravanOrderId,
        webhookEventId: event._id.toString(),
        topic,
        source: 'webhook-app',
      });
      jobId = job.id;

      await this.webhookService.markStatus(
        event._id.toString(),
        WebhookPrivateStatus.QUEUED,
        {
          jobId: job.id,
        },
      );
    } catch (error) {
      // Ghi lỗi để kiểm tra thủ công; vẫn trả 200 để Haravan không gửi lại.
      const message = (error as Error).message;
      this.logger.error(
        `Không thể đưa đơn ${haravanOrderId} vào hàng đợi: ${message}`,
      );
      logWebhookPayload({
        kind: 'app',
        flow: 'event_notification',
        method: req.method,
        path: req.originalUrl ?? null,
        stage: 'processed',
        topic,
        orgId,
        haravanOrderId,
        status: 200,
        result: { outcome: 'loi_khi_tao_job', note: message, headers: picked },
      });
      return { received: true, topic, orgId, queued: false };
    }

    logWebhookPayload({
      kind: 'app',
      flow: 'event_notification',
      method: req.method,
      path: req.originalUrl ?? null,
      stage: 'processed',
      topic,
      orgId,
      haravanOrderId,
      status: 200,
      result: {
        outcome: 'da_day_vao_hang',
        note: 'controller chi tao job, JobWorker se xu ly',
        jobId,
        headers: picked,
      },
    });

    this.logger.log(`App ${topic}: đơn ${haravanOrderId} -> job ${jobId}`);

    return { received: true, topic, orgId, queued: true, jobId };
  }
}
