import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Shop, ShopDocument } from '../webhook-app/webhook-app.entity';
import { UpdateShopSettingsDto } from './dto/update-shop-settings.dto';

@Injectable()
export class ShopSettingsService {
  constructor(
    @InjectModel(Shop.name) private readonly shopModel: Model<ShopDocument>,
  ) {}

  async get(orgId: number) {
    const shop = await this.shopModel
      .findOne({ orgId })
      .select('orgId name domain auto_check_repeat_orders check_order')
      .lean()
      .exec();
    if (!shop) {
      return { orgId, name: '', domain: '', auto_check_repeat_orders: true };
    }
    return {
      orgId: shop.orgId,
      name: shop.name ?? '',
      domain: shop.domain ?? '',
      auto_check_repeat_orders:
        shop.auto_check_repeat_orders ??
        (shop as typeof shop & { check_order?: boolean }).check_order ??
        true,
    };
  }

  async update(orgId: number, dto: UpdateShopSettingsDto) {
    const $set: Record<string, unknown> = {};
    if (dto.name !== undefined) {
      const name = dto.name.trim();
      if (!name) throw new BadRequestException('Shop name cannot be empty');
      $set.name = name;
    }
    if (dto.auto_check_repeat_orders !== undefined) {
      $set.auto_check_repeat_orders = dto.auto_check_repeat_orders;
    }
    const shop = await this.shopModel
      .findOneAndUpdate(
        { orgId },
        { $set, $setOnInsert: { orgId }, $unset: { check_order: 1 } },
        { new: true, upsert: true, setDefaultsOnInsert: true },
      )
      .select('orgId name domain auto_check_repeat_orders')
      .lean()
      .exec();
    if (!shop) {
      return {
        orgId,
        name: String($set.name ?? ''),
        domain: '',
        auto_check_repeat_orders:
          typeof $set.auto_check_repeat_orders === 'boolean'
            ? $set.auto_check_repeat_orders
            : true,
      };
    }
    return {
      orgId: shop.orgId,
      name: shop.name ?? '',
      domain: shop.domain ?? '',
      auto_check_repeat_orders: shop.auto_check_repeat_orders ?? true,
    };
  }

  async isAutoCheckRepeatOrdersEnabled(orgId: number): Promise<boolean> {
    const shop = await this.shopModel
      .findOne({ orgId })
      .select('auto_check_repeat_orders check_order')
      .lean()
      .exec();
    if (!shop) return true;
    return (
      shop.auto_check_repeat_orders ??
      (shop as typeof shop & { check_order?: boolean }).check_order ??
      true
    );
  }
}
