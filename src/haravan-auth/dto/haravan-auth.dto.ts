import { IsOptional, IsString, MaxLength } from 'class-validator';

/** Query cua GET /haravan/auth/login. */
export class HaravanLoginQueryDto {
  /**
   * Trang web cua ban sau khi dang nhap xong. Chi dung khi server khong khai
   * bao HARAVAN_OPENID_FRONTEND_REDIRECT_URI; gia tri phai nam trong danh sach
   * trang duoc cho phep (xem HARAVAN_OPENID_ALLOWED_REDIRECT_HOSTS).
   */
  @IsOptional()
  @IsString()
  @MaxLength(512)
  redirect_uri?: string;

  /** mode=json: tra ve URL cua Haravan thay vi chuyen huong 302. */
  @IsOptional()
  @IsString()
  @MaxLength(16)
  mode?: string;
}

/**
 * Body cua POST /haravan/auth/callback. Haravan gui bang response_mode
 * form_post nen cac truong nay nam trong body, khong phai query string.
 */
export class HaravanCallbackDto {
  @IsOptional()
  @IsString()
  @MaxLength(2048)
  code?: string;

  @IsOptional()
  @IsString()
  @MaxLength(512)
  state?: string;

  @IsOptional()
  @IsString()
  @MaxLength(512)
  scope?: string;

  @IsOptional()
  @IsString()
  @MaxLength(512)
  session_state?: string;

  @IsOptional()
  @IsString()
  @MaxLength(128)
  error?: string;

  @IsOptional()
  @IsString()
  @MaxLength(512)
  error_description?: string;
}

/** Body cua POST /haravan/auth/session: doi ma mot lan lay token. */
export class HaravanSessionDto {
  @IsString()
  @MaxLength(256)
  ticket!: string;
}
