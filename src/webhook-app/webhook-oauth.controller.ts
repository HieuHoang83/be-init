import {
  BadRequestException,
  Controller,
  Get,
  Inject,
  Logger,
  Query,
  Res,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import type { Response } from 'express';
import { appConfig } from '../config';
import { ApiClient, ApiError } from '../api/api.service';
import { logWebhookPayload } from '../core/webhook-payload-logger';
import { AccessTokenStore } from '../api/access-token.store';
import { WebhookAppService } from './webhook-app.service';

/**
 * Callback OAuth của ứng dụng Haravan, từ bước 2 sang bước 3.
 *
 * Sau khi người bán chọn "Confirm install", Haravan chuyển hướng về:
 *   GET {redirect_uri}?code=XXX&scope=YYY&session_state=ZZZ
 *
 * Tuyến này nhận `code`, đổi thành access token qua POST /connect/token và
 * lưu lại để các API sử dụng. Nếu thiếu tuyến này, Haravan sẽ nhận lỗi 404
 * và mã ủy quyền không thể đổi lấy token.
 */
@Controller('webhooks/callback')
export class WebhookOauthController {
  private readonly logger = new Logger(WebhookOauthController.name);

  private readonly cfg: ConfigType<typeof appConfig>['api']['oauth'];

  constructor(
    @Inject(appConfig.KEY) config: ConfigType<typeof appConfig>,
    private readonly api: ApiClient,
    private readonly tokenStore: AccessTokenStore,
    private readonly appService: WebhookAppService,
  ) {
    this.cfg = config.api.oauth;
  }

  @Get()
  async handleCallback(
    @Query('code') code: string | undefined,
    @Query('scope') scope: string | undefined,
    @Query('error') error: string | undefined,
    @Query('error_description') errorDescription: string | undefined,
    @Query('session_state') sessionState: string | undefined,
    @Res() res: Response,
  ): Promise<void> {
    logWebhookPayload({
      kind: 'app',
      flow: 'oauth_callback',
      method: 'GET',
      path: '/api/v1/webhooks/callback',
      result: { co_code: Boolean(code), scope: scope ?? null },
      error: error ?? undefined,
    });

    const configured = {
      clientId: this.cfg.clientId,
      redirectUri: this.cfg.redirectUri,
    };

    // Nếu shop từ chối cấp quyền, trả về lỗi tương ứng.
    if (error) {
      this.logger.warn(`Shop tu cho lai: ${error} - ${errorDescription ?? ''}`);
      return this.reply(res, 400, {
        ok: false,
        error,
        error_description: errorDescription ?? null,
      });
    }

    if (!code) {
      this.logger.warn('Callback khong co tham so `code`');
      return this.reply(res, 400, {
        ok: false,
        error: 'Thieu tham so `code`. Hay mo link can nhep lai app tu trang Haravan Partner Dashboard.',
      });
    }

    if (!configured.clientId || !configured.redirectUri) {
      this.logger.error('Thieu HARAVAN_CLIENT_ID hoac HARAVAN_REDIRECT_URI trong .env');
      return this.reply(res, 500, {
        ok: false,
        error: 'Server chua cau hinh HARAVAN_CLIENT_ID / HARAVAN_REDIRECT_URI',
      });
    }

    this.logger.log(
      `Nhan code (${code.slice(0, 8)}...), scope="${scope ?? ''}", ` +
        `redirect_uri=${configured.redirectUri}`,
    );

    try {
      const res2 = await this.api.exchangeAuthorizationCode(code);
      const token = res2.body;

      const grantedScopes = (token.scope ?? scope ?? '').split(/\s+/).filter(Boolean);

      // Lưu vào cơ sở dữ liệu để tiếp tục sử dụng sau khi khởi động lại.
      const orgId = Number(process.env.HARAVAN_ORG_ID) || 0;
      let savedTo = 'khong luu (thieu HARAVAN_ORG_ID)';
      if (orgId) {
        await this.tokenStore.persist(
          orgId,
          token.access_token,
          token.expires_in ?? 3600,
          grantedScopes,
        );
        savedTo = `shops (org ${orgId})`;
        await this.appService.upsertScopes(orgId, grantedScopes);
      }

      this.logger.log(
        `Doi code thanh cong: token_type=${token.token_type}, ` +
          `expires_in=${token.expires_in}, scope=${token.scope ?? scope}, luu vao ${savedTo}`,
      );

      const hasWhApi = grantedScopes.includes('wh_api');

      // Không trả access_token về trình duyệt.
      return this.reply(res, 200, {
        ok: true,
        saved_to: savedTo,
        token_type: token.token_type ?? null,
        expires_in: token.expires_in ?? null,
        scope: grantedScopes,
        has_refresh_token: Boolean(token.refresh_token),
        has_wh_api: hasWhApi,
        warning: hasWhApi
          ? undefined
          : 'Thieu scope `wh_api` -> chua goi duoc POST webhook.haravan.com/api/subscribe. ' +
            'Phai cap them scope do o Partner Dashboard roi cai lai app.',
      });
    } catch (e) {
      if (e instanceof ApiError) {
        this.logger.error(`Doi code that bai (HTTP ${e.statusCode}): ${e.message}`);
        return this.reply(res, 502, {
          ok: false,
          error: e.message,
          detail: e.body ?? null,
          hint:
            e.statusCode === 400
              ? 'invalid_grant: code da het han / da dung, hoac redirect_uri lech. ' +
                'Can tao code moi va doi ngay.'
              : undefined,
        });
      }
      this.logger.error(`Loi khong mong doi: ${(e as Error).message}`);
      return this.reply(res, 500, { ok: false, error: (e as Error).message });
    }
  }

  private reply(res: Response, status: number, body: unknown): void {
    res.status(status).json(body);
  }
}
