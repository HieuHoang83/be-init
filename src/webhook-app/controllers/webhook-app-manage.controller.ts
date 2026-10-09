import { Body, Controller, Delete, Get, Logger, Post } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { ApiClient } from '../../api/api.service';
import { WebhookAppService } from '../services/webhook-app.service';
import {
  SubscribedWebhookListResponse,
  WebhookSubscribeResponse,
} from '../interfaces/webhook-app.interface';

/** Lấy org_id từ query hoặc body; nếu thiếu thì dùng org_id trong .env. */
function resolveOrgId(from: Record<string, unknown> | undefined): number {
  const raw =
    from?.orgId ?? from?.org_id ?? process.env.HARAVAN_ORG_ID ?? undefined;

  const orgId = Number(raw);
  if (!orgId) {
    throw new Error('Thieu org_id. Gui ?orgId=... hoac dat HARAVAN_ORG_ID');
  }
  return orgId;
}

/**
 * Quản lý đăng ký webhook trên Haravan; các tuyến này được bảo vệ bằng JWT.
 *
 *   POST   /webhooks/app/subscribe    -> đăng ký nhận thông báo
 *   DELETE /webhooks/app/subscribe    -> hủy đăng ký
 *   GET    /webhooks/app/subscribe    -> xem các chủ đề đã đăng ký
 */
@ApiTags('Haravan Webhook (App) - manage')
@Controller('webhooks/app/subscribe')
export class WebhookAppManageController {
  private readonly logger = new Logger(WebhookAppManageController.name);

  constructor(
    private readonly apiClient: ApiClient,
    private readonly appService: WebhookAppService,
  ) {}

  @Post()
  @ApiOperation({ summary: 'Buoc 4: khai bao app duoc nhan webhook' })
  async subscribe(
    @Body() body: Record<string, unknown>,
  ): Promise<WebhookSubscribeResponse> {
    const orgId = resolveOrgId(body);
    this.logger.log(`Dang goi Haravan POST /api/subscribe cho org ${orgId}`);

    const res = await this.apiClient.subscribeWebhook(orgId);
    await this.appService.markSubscribed(orgId);
    return res.body;
  }

  @Delete()
  @ApiOperation({ summary: 'Buoc 7: huy dang ky webhook' })
  async unsubscribe(): Promise<WebhookSubscribeResponse> {
    const orgId = resolveOrgId(undefined);
    this.logger.log(`Dang goi Haravan DELETE /api/subscribe cho org ${orgId}`);

    const res = await this.apiClient.unsubscribeWebhook(orgId);
    return res.body;
  }

  @Get()
  @ApiOperation({ summary: 'Buoc 8: xem topic dang duoc subscribe' })
  async list(): Promise<SubscribedWebhookListResponse> {
    const orgId = resolveOrgId(undefined);
    this.logger.log(`Dang goi Haravan GET /api/subscribe cho org ${orgId}`);

    const res = await this.apiClient.listSubscribedWebhooks(orgId);
    return res.body;
  }

  /** URL callback cần điền trên partners.haravan.com/apps. */
  @Get('callback-url')
  @ApiOperation({ summary: 'Callback URL de dien vao form dang ky webhook' })
  callbackUrl(): { callbackUrl: string; verifyTokenHint: string } {
    const base = process.env.PUBLIC_BASE_URL || '';
    return {
      callbackUrl: `${base}/api/v1/webhooks/app`,
      verifyTokenHint: 'khop voi HARAVAN_APP_VERIFY_TOKEN trong .env',
    };
  }
}
