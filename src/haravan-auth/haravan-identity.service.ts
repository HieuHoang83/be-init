import {
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { UserService, UserWithRole } from '../user/user.service';
import { appConfig } from '../config';
import { HaravanIdentity } from './interfaces/haravan-auth.interface';

/**
 * Chuyen danh tinh Haravan thanh user trong database.
 *
 * Thu tu uu tien:
 *   1. user da lien ket truoc qua `haravanUserId` (truong `sub` cua id_token)
 *   2. user da lien ket truoc qua email Haravan
 *   3. tao user moi neu `HARAVAN_OPENID_AUTO_PROVISION=true` (mac dinh)
 *
 * User moi duoc sinh `phone` dang `haravan-<sub>` de khop duong danh tinh.
 * Nguoi dung nhu vay khong dang nhap duoc bang mat khau, chi bang Haravan.
 */
@Injectable()
export class HaravanIdentityService {
  private readonly logger = new Logger(HaravanIdentityService.name);
  private readonly cfg: ConfigType<typeof appConfig>['openid'];

  constructor(
    @Inject(appConfig.KEY) config: ConfigType<typeof appConfig>,
    private readonly userService: UserService,
  ) {
    this.cfg = config.openid;
  }

  async resolveUser(identity: HaravanIdentity): Promise<UserWithRole> {
    const { sub, email, name, orgId } = identity;

    const linked = await this.userService.findOneByHaravanUserId(sub);
    if (linked) {
      return (await this.userService.touchHaravanLogin(
        linked._id.toString(),
        orgId,
      )) as UserWithRole;
    }

    if (email) {
      const byEmail = await this.userService.findOneByHaravanEmail(email);
      if (byEmail) {
        this.logger.log(
          `Gan tai khoan Haravan ${sub} vao user hien tai (${byEmail.phone})`,
        );
        return (await this.userService.linkHaravanAccount(
          byEmail._id.toString(),
          { haravanUserId: sub, haravanEmail: email, haravanOrgId: orgId },
        )) as UserWithRole;
      }
    }

    if (!this.cfg.autoProvision) {
      throw new ForbiddenException(
        `Tai khoan Haravan ${sub} chua duoc lien ket voi user nao. ` +
          'Hay bat HARAVAN_OPENID_AUTO_PROVISION=true hoac tu gan user trong DB.',
      );
    }

    const role = await this.userService.findRoleByName(this.cfg.defaultRole);
    if (!role) {
      throw new ServiceUnavailableException(
        `Vai tro mac dinh "${this.cfg.defaultRole}" chua ton tai. ` +
          'Chay `npm run seed:admin` de tao vai truoc.',
      );
    }

    const phone = this.buildPhone(sub);

    try {
      const created = await this.userService.create({
        name: name || email || `Haravan ${sub}`,
        phone,
        // Mat khau ngau nhien: user nay chi dang nhap qua Haravan.
        password: `hv_${phone}`,
        roleId: role._id.toString(),
        haravanUserId: sub,
        haravanEmail: email,
        haravanOrgId: orgId,
      });

      this.logger.log(
        `Tao user moi cho tai khoan Haravan ${sub}` +
          (orgId ? ` (org ${orgId})` : '') +
          `, vai tro ${role.name}`,
      );

      return created;
    } catch (error) {
      const code = (error as { code?: number }).code;
      if (code === 11000) {
        throw new ConflictException(
          `Da co user khac chiem sub=${sub} hoac email ${email ?? ''}. ` +
            'Hay kiem tra lai du lieu lien ket tai khoan Haravan.',
        );
      }
      throw error;
    }
  }

  /** So dien thoai gia de, ton tai duy nhat theo `sub`. */
  private buildPhone(sub: string): string {
    const clean = sub.replace(/[^a-zA-Z0-9]/g, '');
    return `haravan-${clean.slice(0, 24)}`;
  }
}
