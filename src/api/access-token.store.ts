import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { Inject } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { appConfig } from '../config';
import { Shop, ShopDocument } from '../webhook-app/webhook-app.entity';

/**
 * Noi lay `haravan-access-token` theo tung shop.
 *
 * Phase 1 (single shop): doc token tu env.
 * Phase 2 (multi shop): tra token da decrypt tu bang `shops`,
 * kem TTL cache de khong phai goi Haravan moi request.
 */
@Injectable()
export class AccessTokenStore {
  private readonly logger = new Logger(AccessTokenStore.name);

  /** orgId -> token, cho multi-shop o phase sau */
  private readonly cache = new Map<number, { token: string; expiresAt: number }>();

  private readonly envToken: string;
  private readonly envOrgId: number | null;

  constructor(
    @Inject(appConfig.KEY) config: ConfigType<typeof appConfig>,
    @InjectModel(Shop.name) private readonly shopModel: Model<ShopDocument>,
  ) {
    this.envToken = config.credentials.accessToken;
    this.envOrgId = config.credentials.orgId;
  }

  async get(orgId: number): Promise<string> {
    const cached = this.cache.get(orgId);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.token;
    }

    // Token tu OAuth callback (da luu o `shops`) duoc uu tien hon env
    const stored = await this.loadFromDb(orgId);
    if (stored) return stored;

    if (this.envToken && (this.envOrgId === null || this.envOrgId === orgId)) {
      return this.envToken;
    }

    this.logger.warn(`Khong tim thay access token cho org ${orgId}`);
    throw new UnauthorizedException(`Chua cau hinh access token cho shop ${orgId}`);
  }

  /** Doc token da luu tu OAuth callback trong collection `shops` */
  private async loadFromDb(orgId: number): Promise<string | null> {
    const shop = await this.shopModel
      .findOne({ orgId })
      .select('+accessToken accessTokenExpiresAt')
      .lean()
      .exec();

    if (!shop?.accessToken) return null;

    if (shop.accessTokenExpiresAt && shop.accessTokenExpiresAt.getTime() <= Date.now()) {
      this.logger.warn(
        `Access token cua org ${orgId} da het han, can doi code OAuth lai`,
      );
      return null;
    }

    return shop.accessToken;
  }

  /** Luu token vua doi xuong DB de dung qua lan restart */
  async persist(
    orgId: number,
    token: string,
    expiresInSec?: number,
    scopes?: string[],
  ): Promise<void> {
    await this.shopModel
      .updateOne(
        { orgId },
        {
          $set: {
            accessToken: token,
            ...(expiresInSec
              ? { accessTokenExpiresAt: new Date(Date.now() + expiresInSec * 1000) }
              : {}),
            ...(scopes?.length ? { scopes } : {}),
          },
          $setOnInsert: { orgId },
        },
        { upsert: true },
      )
      .exec();
    this.set(orgId, token, (expiresInSec ?? 3600) * 1000);
  }

  /** Dung ngay khi vừa doi token trong admin UI */
  set(orgId: number, token: string, ttlMs = 55 * 60 * 1000): void {
    this.cache.set(orgId, { token, expiresAt: Date.now() + ttlMs });
  }
}
