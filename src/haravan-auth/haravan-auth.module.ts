import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { appConfig } from '../config';
import { AuthModule } from '../auth/auth.module';
import { UsersModule } from '../user/user.module';
import { ApiModule } from '../api/api.module';
import { HaravanAuthController } from './haravan-auth.controller';
import { HaravanAuthService } from './haravan-auth.service';
import { HaravanAuthStateService } from './haravan-auth-state.service';
import { HaravanIdentityService } from './haravan-identity.service';
import { HaravanLoginFlowService } from './haravan-login-flow.service';

/**
 * Dang nhap qua Haravan Connect (OpenID Connect).
 *
 * Khong phai proxy resource nen khong dung HaravanGateway; module nay tu goi
 * accounts.haravan.com bang `openid-client` roi cap JWT noi bo cho frontend.
 */
@Module({
  imports: [
    ConfigModule.forFeature(appConfig),
    UsersModule,
    AuthModule,
    // Callback cua luong cai app cung co the quay ve `/haravan/auth/callback`.
    ApiModule,
  ],
  controllers: [HaravanAuthController],
  exports: [
    HaravanAuthService,
    HaravanAuthStateService,
    HaravanIdentityService,
    // `/webhooks/callback` goi `dispatchCallback` khi callback login quay ve
    // endpoint cua luong cai app.
    HaravanLoginFlowService,
  ],
  providers: [
    HaravanAuthService,
    HaravanAuthStateService,
    HaravanIdentityService,
    HaravanLoginFlowService,
  ],
})
export class HaravanAuthModule {}
