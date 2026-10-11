import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import type { Request, Response } from 'express';
import { appConfig } from '../config';
import { ApiClient } from '../api/api.service';
import { AccessTokenStore } from '../api/access-token.store';
import { AuthService } from '../auth/auth.service';
import { UserService, UserWithRole } from '../user/user.service';
import { HaravanAuthService } from './haravan-auth.service';
import { HaravanAuthStateService } from './haravan-auth-state.service';
import { HaravanIdentityService } from './haravan-identity.service';
import {
  HaravanCallbackDto,
  HaravanLoginQueryDto,
} from './dto/haravan-auth.dto';
import {
  HaravanIdentity,
  HaravanLoginSession,
} from './interfaces/haravan-auth.interface';

/**
 * Phan xu ly chung cho callback cua Haravan.
 *
 * Haravan chi cho phep dang ky MOT `redirect_uri` cho mot app, va ca hai luong
 * (cai app de lay access token + dang nhap tai khoan) deu di qua cung mot
 * endpoint `/connect/authorize`. Callback cua ca hai luong luon quay ve cung
 * mot dia chi, nen phai tu phan biet.
 *
 * Cach phan biet: luong DANG NHAP luon kem `state` (sinh o
 * `GET /haravan/auth/login`), con luong CAI APP khong co `state` nao ca.
 */
@Injectable()
export class HaravanLoginFlowService {
  private readonly cfg: ConfigType<typeof appConfig>['openid'];
  private readonly credentials: ConfigType<typeof appConfig>['credentials'];

  constructor(
    @Inject(appConfig.KEY) config: ConfigType<typeof appConfig>,
    private readonly haravanAuth: HaravanAuthService,
    private readonly state: HaravanAuthStateService,
    private readonly identity: HaravanIdentityService,
    private readonly authService: AuthService,
    private readonly userService: UserService,
    private readonly api: ApiClient,
    private readonly tokenStore: AccessTokenStore,
  ) {
    this.cfg = config.openid;
    this.credentials = config.credentials;
  }

  /** Callback nao la dang nhap, callback nao la cai app. */
  isAppInstallCallback(dto: HaravanCallbackDto): boolean {
    return !dto.state;
  }

  /**
   * Entry point cho moi callback (GET hoac POST, o endpoint nao cung duoc).
   * Tu phan biet luong roi tra loi hoac chuyen huong ve frontend.
   */
  async dispatchCallback(
    dto: HaravanCallbackDto,
    req: Request,
    res: Response,
  ): Promise<Response | void> {
    const requestUrl = this.requestUrl(req);

    if (this.isAppInstallCallback(dto)) {
      return this.handleAppInstall(dto, requestUrl, res);
    }

    const { identity, redirectUri } =
      await this.haravanAuth.resolveIdentity({
        ...dto,
        redirectUri: requestUrl,
      });
    const user = await this.identity.resolveUser(identity);
    const session = await this.issueSession(user, identity);

    // Khong co frontend: tra JSON de app/mobile tu lay token.
    const frontendRedirectUri = redirectUri ?? this.cfg.frontendRedirectUri;
    if (!frontendRedirectUri) {
      return res.status(200).json(session);
    }

    // Co frontend: chuyen huong ve mot ma dung mot lan thay vi de access token
    // trong query string (anh xinh qua proxy/log).
    const ticket = this.state.issueTicket(user._id.toString());
    return res.redirect(this.withTicket(frontendRedirectUri, ticket));
  }

  /**
   * Callback cua luong CAI APP (khong co `state`): doi code lay access token de
   * goi API roi luu vao `shops`. Giong logic cua `/webhooks/callback`, chi la
   * Haravan co the tra ve endpoint nay thay vi endpoint do.
   */
  private async handleAppInstall(
    dto: HaravanCallbackDto,
    requestUrl: string,
    res: Response,
  ): Promise<Response | void> {
    if (dto.error) {
      return res.status(400).json({
        statusCode: 400,
        message: `Shop tu cho lai: ${dto.error}`,
        error: dto.error,
      });
    }

    if (!dto.code) {
      throw new BadRequestException(
        'Thieu tham so `code`. Hay mo lai link can nhep app tu trang Haravan.',
      );
    }

    const result = await this.api.exchangeAuthorizationCode(
      dto.code,
      requestUrl,
    );
    const token = result.body;
    const grantedScopes = (token.scope ?? dto.scope ?? '')
      .split(/\s+/)
      .filter(Boolean);

    const orgId = this.credentials.orgId ?? 0;
    if (orgId) {
      await this.tokenStore.persist(
        orgId,
        token.access_token,
        token.expires_in ?? 3600,
        grantedScopes,
      );
    }

    return res.status(200).json({
      statusCode: 200,
      message: 'Doi code thanh cong',
      data: {
        ok: true,
        org_id: orgId || null,
        token_type: token.token_type ?? null,
        expires_in: token.expires_in ?? null,
        scope: grantedScopes,
        has_refresh_token: Boolean(token.refresh_token),
      },
    });
  }

  /** Sinh access/refresh token noi bo cho user vua dang nhap. */
  async issueSession(
    user: UserWithRole,
    identity?: HaravanIdentity,
  ): Promise<HaravanLoginSession> {
    const payload = {
      id: user._id.toString(),
      name: user.name,
      phone: user.phone,
      role: user.role?.name,
    };

    const refresh_token = this.authService.createRefreshToken(payload);
    const access_token = this.authService.createAccessToken(payload);

    await this.userService.updateRefreshToken(payload.id, refresh_token);

    return {
      user: {
        id: payload.id,
        name: user.name,
        phone: user.phone,
        avatar: user.avatar,
        role: payload.role,
      },
      token: { access_token, refresh_token },
      haravan: {
        sub: identity?.sub ?? user.haravanUserId ?? '',
        email: identity?.email ?? user.haravanEmail,
        orgId: identity?.orgId ?? user.haravanOrgId,
        role: identity?.role,
      },
    };
  }

  /**
   * `redirect_uri` phai trung tuyet doi voi dia chi Haravan vua chuyen huong toi,
   * nen lay tu chinh request dang xu ly thay vi hard-code trong `.env`.
   */
  private requestUrl(req: Request): string {
    return `${req.protocol}://${req.get('host')}${req.originalUrl.split('?')[0]}`;
  }

  private withTicket(base: string, ticket: string): string {
    const url = new URL(base);
    url.searchParams.set('code', ticket);
    return url.toString();
  }
}
