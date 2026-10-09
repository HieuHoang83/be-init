import { Injectable } from '@nestjs/common';
import { ApiClient } from '../api/api.service';
import { HaravanGateway } from '../api/haravan.gateway';

/**
 * Service proxy tài nguyên Haravan của module haravan-product.
 * Mỗi module chỉ có các endpoint thuộc đúng tài nguyên của nó.
 */
@Injectable()
export class HaravanProductService extends HaravanGateway {
  constructor(apiClient: ApiClient) {
    super(apiClient);
  }


  listProducts(orgId: number, query: object) {
    return this.forward(orgId, 'GET', '/products.json', undefined, query);
  }

  countProducts(orgId: number, query: object) {
    return this.forward(orgId, 'GET', '/products/count.json', undefined, query);
  }

  getProduct(orgId: number, productId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      `/products/${productId}.json`,
      undefined,
      query,
    );
  }

  createProduct(orgId: number, body: object) {
    return this.forward(orgId, 'POST', '/products.json', body);
  }

  updateProduct(orgId: number, productId: number, body: object) {
    return this.forward(orgId, 'PUT', `/products/${productId}.json`, body);
  }

  deleteProduct(orgId: number, productId: number) {
    return this.forward(orgId, 'DELETE', `/products/${productId}.json`, {});
  }

  addProductTags(orgId: number, productId: number, body: object) {
    return this.forward(
      orgId,
      'POST',
      `/products/${productId}/tags.json`,
      body,
    );
  }

  removeProductTags(orgId: number, productId: number, body: object) {
    return this.forward(
      orgId,
      'DELETE',
      `/products/${productId}/tags.json`,
      body,
    );
  }

  listProductVariants(orgId: number, productId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      `/products/${productId}/variants.json`,
      undefined,
      query,
    );
  }

  countProductVariants(orgId: number, productId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      `/products/${productId}/variants/count.json`,
      undefined,
      query,
    );
  }

  getVariant(orgId: number, variantId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      `/variants/${variantId}.json`,
      undefined,
      query,
    );
  }

  createProductVariant(orgId: number, productId: number, body: object) {
    return this.forward(
      orgId,
      'POST',
      `/products/${productId}/variants.json`,
      body,
    );
  }

  updateProductVariant(orgId: number, variantId: number, body: object) {
    return this.forward(orgId, 'PUT', `/variants/${variantId}.json`, body);
  }

  deleteProductVariant(orgId: number, productId: number, variantId: number) {
    return this.forward(
      orgId,
      'DELETE',
      `/products/${productId}/variants/${variantId}.json`,
      {},
    );
  }
}
