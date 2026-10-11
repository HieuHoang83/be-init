import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { Inject } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { Request, Response } from 'express';
import { Public, ResponseMessage, User } from '../decorators/customize';
import { IUser } from '../interface/users.interface';
import { AuthService } from '../auth/auth.service';
import { UserService, UserWithRole } from '../user/user.service';
import { appConfig } from '../config';
import { HaravanAuthService } from './haravan-auth.service';
import { HaravanAuthStateService } from './haravan-auth-state.service';
import { HaravanIdentityService } from './haravan-identity.service';
import { HaravanLoginFlowService } from './haravan-login-flow.service';
import {
  HaravanCallbackDto,
  HaravanLoginQueryDto,
  HaravanSessionDto,
} from './dto/haravan-auth.dto';
import {
  HaravanIdentity,
  HaravanLoginSession,
} from './interfaces/haravan-auth.interface';

/**
 * Dang nhap bang tai khoan Haravan (Haravan Connect / OpenID Connect).
 *
 *   GET  /api/v1/haravan/auth/login     -> chuyen huong sang Haravan
 *   POST /api/v1/haravan/auth/callback  -> Haravan gui code (form_post)
 *   POST /api/v1/haravan/auth/session   -> doi ticket lay access/refresh token
 *   GET  /api/v1/haravan/auth/me        -> thong tin tai khoan vua lien ket
 *   GET  /api/v1/haravan/auth/logout    -> huy token noi bo + logout Haravan
 */
@ApiTags('Haravan Auth')
@Controller('haravan/auth')
export class HaravanAuthController {
  private readonly cfg: ConfigType<typeof appConfig>['openid'];

  constructor(
    @Inject(appConfig.KEY) config: ConfigType<typeof appConfig>,
    private readonly haravanAuth: HaravanAuthService,
    private readonly state: HaravanAuthStateService,
    private readonly identity: HaravanIdentityService,
    private readonly authService: AuthService,
    private readonly userService: UserService,
    private readonly flow: HaravanLoginFlowService,
  ) {
    this.cfg = config.openid;
  }

  @Public()
  @Get('login')
  @ApiOperation({ summary: 'Bat dau dang nhap bang tai khoan Haravan' })
  async login(
    @Query() query: HaravanLoginQueryDto,
    @Res() res: Response,
  ): Promise<void> {
    const redirectUri = this.resolveRedirectUri(query.redirect_uri);
    const url = await this.haravanAuth.buildLoginUrl(redirectUri);

    // mode=json tien cho mobile/Postman; mac dinh chuyen huong trinh duyet.
    if (query.mode === 'json') {
      res.status(200).json({ authorization_url: url.toString() });
      return;
    }

    res.redirect(url.toString());
  }

  @Public()
  @Post('callback')
  @ApiOperation({
    summary: 'Haravan gui code tro ve (response_mode=form_post)',
  })
  async callback(
    @Body() dto: HaravanCallbackDto,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    await this.flow.dispatchCallback(dto, req, res);
  }

  /**
   * Haravan cung cap theo ca hai kieu chuyen huong: `form_post` (POST) va
   * query string (GET). Thieu GET thi nguoi dung dang nhap tren trinh duyet
   * duoc chuyen huong ve day nhan duoc `Cannot GET ...` roi cham tai day.
   */
  @Public()
  @Get('callback')
  @ApiOperation({ summary: 'Haravan gui code tro ve qua query string (GET)' })
  async callbackGet(
    @Query() query: HaravanCallbackDto,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    await this.flow.dispatchCallback(query, req, res);
  }

  @Public()
  @Post('session')
  @ApiOperation({ summary: 'Doi ticket (lay sau khi callback) lay token' })
  async exchangeTicket(@Body() dto: HaravanSessionDto) {
    const ticket = this.state.consumeTicket(dto.ticket);
    const user = await this.userService.findOneById(ticket.userId);

    return this.flow.issueSession(user);
  }

  @ApiBearerAuth('token')
  @Get('me')
  @ResponseMessage('Thong tin tai khoan')
  @ApiOperation({ summary: 'Thong tin tai khoan Haravan da lien ket' })
  async me(@User() current: IUser) {
    const user = await this.userService.findOneById(current.id);

    return {
      id: user._id.toString(),
      name: user.name,
      phone: user.phone,
      avatar: user.avatar,
      role: user.role?.name,
      haravan: {
        user_id: user.haravanUserId ?? null,
        email: user.haravanEmail ?? null,
        org_id: user.haravanOrgId ?? null,
        last_login_at: user.haravanLoginAt ?? null,
      },
    };
  }

  @ApiBearerAuth('token')
  @Get('logout')
  @ResponseMessage('Logout success')
  @ApiOperation({
    summary: 'Huy token noi bo, tra ve duong dan logout cua Haravan',
  })
  async logout(
    @User() current: IUser,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.logout(current, res);

    const user = await this.userService.findOneById(current.id);

    return {
      ok: true,
      // Harovan chua cap id_token cho BE nen logout phia ho co the can
      // nguoi dung bam nut tren trang Haravan.
      haravan_logout_url: await this.haravanAuth
        .buildLogoutUrl()
        .catch(() => null),
      user_id: user.haravanUserId ?? null,
    };
  }

  /**
   * `redirect_uri` tu frontend chi duoc dung khi host nam trong danh sach
   * cho phep, tranh bien thanh `redirect_uri` cua Haravan thanh cong cong khai.
   */
  private resolveRedirectUri(value?: string): string | undefined {
    if (!value) return this.cfg.frontendRedirectUri || undefined;

    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new BadRequestException('redirect_uri khong hop le.');
    }

    if (!['http:', 'https:'].includes(url.protocol)) {
      throw new BadRequestException('redirect_uri phai la http hoac https.');
    }

    const allowed = this.cfg.allowedRedirectHosts;
    if (allowed.length && !allowed.includes(url.hostname)) {
      throw new BadRequestException(
        `Host "${url.hostname}" khong nam trong danh sach cho phep ` +
          '(HARAVAN_OPENID_ALLOWED_REDIRECT_HOSTS).',
      );
    }

    return value;
  }

}
