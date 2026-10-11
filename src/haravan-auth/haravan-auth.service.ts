import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import * as oauth from 'openid-client';
import { appConfig } from '../config';
import { HaravanAuthStateService } from './haravan-auth-state.service';
import {
  HaravanIdentity,
  HaravanLoginResult,
} from './interfaces/haravan-auth.interface';

/**
 * Lop wrapper quanh `openid-client` cho luong dang nhap Haravan Connect.
 *
 *   GET  /haravan/auth/login    -> chuyen huong sang accounts.haravan.com
 *   POST /haravan/auth/callback -> doi `code` lay token, tra ve claims nguoi dung
 *
 * Mac dinh dung Authorization Code Flow + PKCE. `openid-client` tu kiem tra
 * chu ky id_token (JWKS), `nonce`, `state`, `iss` va `aud`.
 */
@Injectable()
export class HaravanAuthService {
  private readonly logger = new Logger(HaravanAuthService.name);
  private readonly cfg: ConfigType<typeof appConfig>['openid'];

  /** Discovery goi 1 lan duy nhat, cac request sau dung ban cache. */
  private clientPromise: Promise<oauth.Configuration> | null = null;

  constructor(
    @Inject(appConfig.KEY) config: ConfigType<typeof appConfig>,
    private readonly state: HaravanAuthStateService,
  ) {
    this.cfg = config.openid;
  }

  /** Bat khi `HARAVAN_OPENID_ENABLED=false` hoac thieu client_id/redirect_uri. */
  assertEnabled(): void {
    if (!this.cfg.enabled) {
      throw new ServiceUnavailableException(
        'Dang nhap qua Haravan dang bi tat (HARAVAN_OPENID_ENABLED=false).',
      );
    }

    const missing = (
      [
        ['HARAVAN_OPENID_CLIENT_ID', this.cfg.clientId],
        ['HARAVAN_OPENID_CLIENT_SECRET', this.cfg.clientSecret],
        ['HARAVAN_OPENID_REDIRECT_URI', this.cfg.redirectUri],
      ] as const
    )
      .filter(([, value]) => !value)
      .map(([name]) => name);

    if (missing.length) {
      throw new ServiceUnavailableException(
        `Thieu bien moi truong cho dang nhap Haravan: ${missing.join(', ')}`,
      );
    }
  }

  /**
   * Tao URL chuyen huong sang trang dang nhap cua Haravan.
   * `redirectUri` la trang frontend quay ve sau khi xu ly callback.
   */
  async buildLoginUrl(redirectUri?: string): Promise<URL> {
    this.assertEnabled();

    const client = await this.getClient();

    const state = oauth.randomState();
    const nonce = oauth.randomNonce();
    const codeVerifier = oauth.randomPKCECodeVerifier();

    this.state.saveState(state, { nonce, codeVerifier, redirectUri });

    const params: Record<string, string> = {
      redirect_uri: this.cfg.redirectUri,
      scope: this.cfg.scope,
      response_type: this.cfg.responseType,
      state,
      nonce,
      code_challenge: await oauth.calculatePKCECodeChallenge(codeVerifier),
      code_challenge_method: 'S256',
    };

    // `prompt=consent` bat nguoi dung phai duyet lai quyen moi lan dang nhap
    // thay vi con session Haravan la vao thang.
    if (this.cfg.prompt) params.prompt = this.cfg.prompt;

    return oauth.buildAuthorizationUrl(client, params);
  }

  /**
   * Xu ly callback cua Haravan: doi `code` lay token, tra ve danh tinh nguoi dung.
   * `params` lay tu body cua request (Haravan gui `response_mode=form_post`).
   */
  async resolveIdentity(params: {
    code?: string;
    state?: string;
    error?: string;
    error_description?: string;
    /**
     * URL Haravan vua chuyen huong toi. Token request bat buoc phai trung
     * `redirect_uri` cua buoc cap quyen, nen lay dung dia chi nhan request.
     */
    redirectUri?: string;
  }): Promise<HaravanLoginResult> {
    this.assertEnabled();

    if (params.error) {
      throw new BadRequestException(
        `Nguoi dung tu choi quyen truy cap: ${params.error}` +
          (params.error_description ? ` - ${params.error_description}` : ''),
      );
    }

    if (!params.code) {
      throw new BadRequestException(
        'Thieu tham so `code`. Hay mo lai link dang nhap tu dau.',
      );
    }

    // State dung mot lan: request lai hoac gia mao se bi tu choi o day.
    const saved = this.state.consumeState(params.state);
    const client = await this.getClient();

    const currentUrl = new URL(params.redirectUri || this.cfg.redirectUri);
    currentUrl.searchParams.set('code', params.code);
    if (params.state) currentUrl.searchParams.set('state', params.state);

    try {
      const tokens = await oauth.authorizationCodeGrant(client, currentUrl, {
        pkceCodeVerifier: saved.codeVerifier,
        expectedNonce: saved.nonce,
        expectedState: params.state,
      });

      const claims = tokens.claims() as Record<string, unknown> | undefined;

      // Userinfo bo sung truong con thieu (email, orgid) neu id_token khong co.
      const info = tokens.access_token
        ? await oauth
            .fetchUserInfo(
              client,
              tokens.access_token,
              (claims?.sub as string | undefined) ?? oauth.skipSubjectCheck,
            )
            .catch((error: Error) => {
              this.logger.warn(`Userinfo khong goi duoc: ${error.message}`);
              return undefined;
            })
        : undefined;

      const merged: Record<string, unknown> = {
        ...(info ?? {}),
        ...(claims ?? {}),
      };

      const sub = pickString(merged.sub);
      if (!sub) {
        throw new UnauthorizedException(
          'Haravan khong tra ve `sub` trong id_token.',
        );
      }

      const identity: HaravanIdentity = {
        sub,
        email: pickString(merged.email),
        name:
          pickString(merged.name, merged.given_name) ??
          pickString(merged.email),
        phone: pickString(merged.phone_number, merged.phone),
        orgId: pickNumber(merged.orgid, merged.org_id, merged.organization_id),
        role: pickString(merged.role, merged.user_role),
        claims: merged,
      };

      this.assertOrgAllowed(identity.orgId);

      this.logger.log(
        `Dang nhap thanh cong: sub=${sub}` +
          (identity.email ? `, email=${identity.email}` : '') +
          (identity.orgId ? `, org=${identity.orgId}` : ''),
      );

      return { identity, redirectUri: saved.redirectUri };
    } catch (error) {
      if (
        error instanceof BadRequestException ||
        error instanceof UnauthorizedException ||
        error instanceof ForbiddenException
      ) {
        throw error;
      }

      const message = (error as Error).message;
      // `openid-client` nem loi chung chung, chi tiet nam o `error` /
      // `error_description` nen phai lay ra roi log lai.
      const detail = error as Error & {
        error?: string;
        error_description?: string;
        code?: string;
      };
      this.logger.error(
        `Doi code that bai: ${message}` +
          (detail.error ? ` (error=${detail.error})` : '') +
          (detail.error_description ? ` - ${detail.error_description}` : ''),
      );
      throw new UnauthorizedException(
        `Doi code cua Haravan that bai: ${message}` +
          (detail.error_description ? ` - ${detail.error_description}` : ''),
      );
    }
  }

  /** URL logout phia Haravan (RP-Initiated Logout); null neu server khong ho tro. */
  async buildLogoutUrl(idToken?: string): Promise<string | null> {
    this.assertEnabled();

    const client = await this.getClient();
    const params: Record<string, string> = {};

    if (idToken) params.id_token_hint = idToken;
    if (this.cfg.frontendRedirectUri) {
      params.post_logout_redirect_uri = this.cfg.frontendRedirectUri;
    }

    if (!client.serverMetadata().end_session_endpoint) return null;

    return oauth.buildEndSessionUrl(client, params).toString();
  }

  private assertOrgAllowed(orgId?: number): void {
    if (!this.cfg.orgId) return;

    if (orgId !== this.cfg.orgId) {
      throw new ForbiddenException(
        `Tai khoan Haravan khong thuoc shop ${this.cfg.orgId}` +
          (orgId ? ` (shop ${orgId})` : '') +
          '.',
      );
    }
  }

  private getClient(): Promise<oauth.Configuration> {
    if (!this.clientPromise) {
      this.clientPromise = oauth
        .discovery(
          new URL(this.cfg.issuer),
          this.cfg.clientId,
          this.cfg.clientSecret,
        )
        .catch((error: Error) => {
          // Khong cache loi: request sau se thu discovery lai.
          this.clientPromise = null;
          this.logger.error(
            `Khong doc duoc OpenID Configuration cua ${this.cfg.issuer}: ${error.message}`,
          );
          throw new ServiceUnavailableException(
            `Khong ket noi duoc Haravan Connect (${this.cfg.issuer}): ${error.message}`,
          );
        });
    }

    return this.clientPromise;
  }
}

function pickString(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return undefined;
}

function pickNumber(...values: unknown[]): number | undefined {
  for (const value of values) {
    const num = Number(value);
    if (Number.isFinite(num) && num > 0) return num;
  }
  return undefined;
}
