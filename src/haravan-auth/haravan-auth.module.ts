import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { appConfig } from '../config';
import { AuthModule } from '../auth/auth.module';
import { UsersModule } from '../user/user.module';
import { HaravanAuthController } from './haravan-auth.controller';
import { HaravanAuthService } from './haravan-auth.service';
import { HaravanAuthStateService } from './haravan-auth-state.service';
import { HaravanIdentityService } from './haravan-identity.service';

/**
 * Dang nhap qua Haravan Connect (OpenID Connect).
 *
 * Khong phai proxy resource nen khong dung HaravanGateway; module nay tu goi
 * accounts.haravan.com bang `openid-client` roi cap JWT noi bo cho frontend.
 */
@Module({
  imports: [ConfigModule.forFeature(appConfig), UsersModule, AuthModule],
  controllers: [HaravanAuthController],
  providers: [
    HaravanAuthService,
    HaravanAuthStateService,
    HaravanIdentityService,
  ],
  exports: [
    HaravanAuthService,
    HaravanAuthStateService,
    HaravanIdentityService,
  ],
})
export class HaravanAuthModule {}
