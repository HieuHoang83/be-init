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
import { Public } from '../decorators/customize';
import { extractOrder, extractOrgId, extractTopic } from '../core/webhook-payload.util';
import { HmacRequest } from '../core/webhook-hmac.guard';
import { HMAC_HEADER } from '../core/webhook-hmac.util';
import { logWebhookPayload } from '../core/webhook-payload-logger';
import { OrderService } from '../order/order.service';
import { JobQueue, JOB_NAMES } from '../queue/queue.service';
import { WebhookPrivateStatus } from '../webhook-private/webhook-private.entity';
import { WebhookPrivateService } from '../webhook-private/webhook-private.service';
import { WebhookAppHmacGuard } from './webhook-app.guard';
import { WebhookAppService } from './webhook-app.service';

/** Chi luu header can cho audit */
function pickHeaders(headers: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (typeof value === 'string') out[key] = value;
  }
  return out;
}

/**
 * WEBHOOK KET NOI APP (app-based webhook).
 *
 * Khac webhook rieng tu o `webhook-private` o cho co buoc SUBSCRIBE:
 *   1. App goi GET voi hub.mode=subscribe, hub.verify_token, hub.challenge.
 *      Server tra ve NGUYEN gia tri hub.challenge (raw, khong boc JSON).
 *   2. Sau do moi nhan duoc POST thong bao.
 *
 * Secret verify HMAC lay tu bang goc `app_installations`, khong phai secret
 * trong trang Thong bao.
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

  /**
   * Buoc 1 - Subscribe. Tra raw `hub.challenge`.
   * Chi cho HTTPS, nen deploy sau HTTPS truoc khi app goi endpoint nay.
   */
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
      this.logger.warn('Subscribe thieu hub.verify_token hoac hub.challenge');
      throw new BadRequestException('Missing hub.verify_token hoac hub.challenge');
    }

    const orgId = extractOrgId(req.headers, { org_id: orgIdQuery });

    const ok = await this.appService.verifySubscriptionToken(orgId, verifyToken);

    // Ghi lai file: cho biet day co phai buoc verify_token khong, va co khop khong
    logWebhookPayload({
      kind: 'app',
      flow: 'verify_token',
      method: req.method,
      path: req.originalUrl ?? null,
      orgId,
      status: ok ? 200 : 401,
      headers: {
        'x-haravan-org-id': String(orgId ?? ''),
        'haravan_hub_mode': mode ?? '',
        'haravan_hub_verify_token': verifyToken,
        'haravan_hub_challenge': challenge,
      },
      result: {
        outcome: ok ? 'verify_token_khop' : 'verify_token_khong_khop',
        // KHONG ghi gia tri token, chi ghi do dai de doi chieu
        verifyTokenLength: verifyToken.length,
        challengeLength: challenge.length,
      },
      error: ok ? undefined : 'verify_token khong khop',
    });

    if (!ok) {
      this.logger.warn('verify_token khong khop, tra 401');
      throw new UnauthorizedException('Invalid verify token');
    }

    if (orgId) {
      await this.appService.beginSubscription({ orgId, verifyToken });
      await this.appService.confirmSubscription(orgId);
    }

    this.logger.log(`Subscribe thanh cong (mode=${mode ?? 'subscribe'})`);
    res.status(200).type('text/plain').send(String(challenge));
  }

  /**
   * Buoc 2 - Nhan thong bao. Haravan yeu cau tra 200 trong 5 giay nen
   * controller KHONG lam viec nang: chi day job vao hang roi tra luon.
   * `JobWorker` se claim job roi luu don + khach trong `OrderWorker`.
   *
   * App gui ca `orders/create` LAN `orders/updated` cho cung mot don:
   *   - `create`  -> tao ban ghi don, thuong THIEU ten/sdt
   *   - `updated` -> bo sung ten/sdt/so don da mua (nguon chinh de biet khach cu)
   * Ca hai deu chay, va chi ghi de field co gia tri nen don khong bi mat du lieu.
   */
  @Post()
  @HttpCode(200)
  @UseGuards(WebhookAppHmacGuard)
  @ApiOperation({ summary: 'Nhan thong bao tu app webhook' })
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
    const topic = extractTopic(headers, envelope);
    const orgId = extractOrgId(headers, envelope);
    const picked = pickHeaders(headers);

    // extractOrder xu ly ca 3 dang body: order thang, { data }, { data: { order } }
    const parsed = extractOrder(headers, envelope);
    const order = parsed.order as unknown as Record<string, unknown> | null;
    const haravanOrderId = Number(order?.id);

    // Khong du du lieu -> van tra 200, neu tra loi Haravan se retry lien tuc
    if (!orgId || !haravanOrderId) {
      this.logger.warn(
        `App webhook bo qua: thieu orgId hoac id don (topic ${topic}, org ${orgId ?? 'n/a'})`,
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
          note: 'thieu orgId hoac order.id -> van tra 200 de Haravan khong retry',
          headers: picked,
        },
      });
      return { received: true, topic, orgId };
    }

    /**
     * Job mang dung `haravanOrderId`, KHONG mang ca payload.
     *
     * Payload webhook co the 5-50KB (don nhieu san pham + dia chi). Dua
     * nguyen payload vao `jobs` lam bang phinh toang vo khong. Worker tai
     * `haravan-order/{orgId}-{haravanOrderId}` trong `WebhookPrivateService`.
     * Sau khi worker ghi xong don moi den luu - nen don luon la ban moi nhat.
     */
    let jobId: string | undefined;
    try {
      // Luu payload de worker tai lai. `record` la bang audit chung,
      // nen app webhook cung dung, khong can bang rieng.
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

      await this.webhookService.markStatus(event._id.toString(), WebhookPrivateStatus.QUEUED, {
        jobId: job.id,
      });
    } catch (error) {
      // Queue/HTTP co the chet luc nao - tra 200 de Harovan khong retry,
      // job da mat nen ghi ro de can doi chieu thu cong.
      const message = (error as Error).message;
      this.logger.error(`Khong day duoc job cho don ${haravanOrderId}: ${message}`);
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

    this.logger.log(`App ${topic}: don ${haravanOrderId} -> job ${jobId}`);

    return { received: true, topic, orgId, queued: true, jobId };
  }
}
