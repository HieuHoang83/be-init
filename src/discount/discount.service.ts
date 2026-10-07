import { Injectable } from '@nestjs/common';
import { ApiClient } from '../api/api.service';
import { compactQuery, mapHaravanError } from '../api/haravan.util';

/**
 * Proxy Haravan Discount + Promotion Omni API.
 * - DiscountCode: `/com/discounts.json`
 * - Promotion:    `/com/promotions.json`
 *
 * Lưu ý: enable/disable của cả hai resource đều đi qua
 * `/com/discounts/{id}/enable|disable.json` (theo tài liệu Haravan).
 */
@Injectable()
export class DiscountService {
  constructor(private readonly api: ApiClient) {}

  list(orgId: number, query: object) {
    return this.forward(orgId, 'GET', '/discounts.json', undefined, query);
  }

  getOne(orgId: number, discountId: number, query?: object) {
    return this.forward(
      orgId,
      'GET',
      `/discounts/${discountId}.json`,
      undefined,
      query,
    );
  }

  create(orgId: number, body: object) {
    return this.forward(orgId, 'POST', '/discounts.json', body);
  }

  remove(orgId: number, discountId: number) {
    return this.forward(orgId, 'DELETE', `/discounts/${discountId}.json`, {});
  }

  listPromotions(orgId: number, query: object) {
    return this.forward(orgId, 'GET', '/promotions.json', undefined, query);
  }

  getPromotion(orgId: number, promotionId: number, query?: object) {
    return this.forward(
      orgId,
      'GET',
      `/promotions/${promotionId}.json`,
      undefined,
      query,
    );
  }

  createPromotion(orgId: number, body: object) {
    return this.forward(orgId, 'POST', '/promotions.json', body);
  }

  removePromotion(orgId: number, promotionId: number) {
    return this.forward(orgId, 'DELETE', `/promotions/${promotionId}.json`, {});
  }

  /** PUT /com/discounts/{id}/enable.json — dùng cho cả discount và promotion. */
  enable(orgId: number, id: number) {
    return this.forward(orgId, 'PUT', `/discounts/${id}/enable.json`, {});
  }

  /** PUT /com/discounts/{id}/disable.json — dùng cho cả discount và promotion. */
  disable(orgId: number, id: number) {
    return this.forward(orgId, 'PUT', `/discounts/${id}/disable.json`, {});
  }

  private async forward(
    orgId: number,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    path: string,
    body?: object,
    query?: object,
  ) {
    try {
      const res = await this.api.call(
        orgId,
        method,
        path,
        body as Record<string, unknown> | undefined,
        query ? compactQuery(query as Record<string, unknown>) : undefined,
      );
      return res.body;
    } catch (error) {
      mapHaravanError(error);
    }
  }
}
