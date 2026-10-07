import { Injectable } from '@nestjs/common';
import { ApiClient } from '../api/api.service';
import { compactQuery, mapHaravanError } from './haravan.util';

@Injectable()
export class HaravanOmniService {
  constructor(private readonly api: ApiClient) {}

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

  listCustomers(orgId: number, query: object) {
    return this.forward(orgId, 'GET', '/customers.json', undefined, query);
  }

  searchCustomers(orgId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      '/customers/search.json',
      undefined,
      query,
    );
  }

  countCustomers(orgId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      '/customers/count.json',
      undefined,
      query,
    );
  }

  getCustomer(orgId: number, customerId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      `/customers/${customerId}.json`,
      undefined,
      query,
    );
  }

  createCustomer(orgId: number, body: object) {
    return this.forward(orgId, 'POST', '/customers.json', body);
  }

  updateCustomer(orgId: number, customerId: number, body: object) {
    return this.forward(orgId, 'PUT', `/customers/${customerId}.json`, body);
  }

  deleteCustomer(orgId: number, customerId: number) {
    return this.forward(orgId, 'DELETE', `/customers/${customerId}.json`, {});
  }

  addCustomerTags(orgId: number, customerId: number, body: object) {
    return this.forward(
      orgId,
      'POST',
      `/customers/${customerId}/tags.json`,
      body,
    );
  }

  removeCustomerTags(orgId: number, customerId: number, body: object) {
    return this.forward(
      orgId,
      'DELETE',
      `/customers/${customerId}/tags.json`,
      body,
    );
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
