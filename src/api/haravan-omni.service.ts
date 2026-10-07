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

  listLocations(orgId: number, query: object) {
    return this.forward(orgId, 'GET', '/locations.json', undefined, query);
  }

  getLocation(orgId: number, locationId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      `/locations/${locationId}.json`,
      undefined,
      query,
    );
  }

  listInventoryLocations(orgId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      '/inventory_locations.json',
      undefined,
      query,
    );
  }

  /**
   * Chinh sua ton kho theo kho: POST /com/inventories/adjustorset.json.
   * Body: { inventory: { location_id, type: 'adjust' | 'set', reason, note,
   * line_items: [{ product_id, product_variant_id, quantity }] } }
   */
  adjustInventory(orgId: number, body: object) {
    return this.forward(orgId, 'POST', '/inventories/adjustorset.json', body);
  }

  listCollections(orgId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      '/custom_collections.json',
      undefined,
      query,
    );
  }

  countCollections(orgId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      '/custom_collections/count.json',
      undefined,
      query,
    );
  }

  getCollection(orgId: number, collectionId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      `/custom_collections/${collectionId}.json`,
      undefined,
      query,
    );
  }

  createCollection(orgId: number, body: object) {
    return this.forward(orgId, 'POST', '/custom_collections.json', body);
  }

  updateCollection(orgId: number, collectionId: number, body: object) {
    return this.forward(
      orgId,
      'PUT',
      `/custom_collections/${collectionId}.json`,
      body,
    );
  }

  deleteCollection(orgId: number, collectionId: number) {
    return this.forward(
      orgId,
      'DELETE',
      `/custom_collections/${collectionId}.json`,
      {},
    );
  }

  listCollects(orgId: number, query: object) {
    return this.forward(orgId, 'GET', '/collects.json', undefined, query);
  }

  countCollects(orgId: number, query: object) {
    return this.forward(orgId, 'GET', '/collects/count.json', undefined, query);
  }

  getCollect(orgId: number, collectId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      `/collects/${collectId}.json`,
      undefined,
      query,
    );
  }

  createCollect(orgId: number, body: object) {
    return this.forward(orgId, 'POST', '/collects.json', body);
  }

  deleteCollect(orgId: number, collectId: number) {
    return this.forward(orgId, 'DELETE', `/collects/${collectId}.json`, {});
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

  listCustomerAddresses(orgId: number, customerId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      `/customers/${customerId}/addresses.json`,
      undefined,
      query,
    );
  }

  getCustomerAddress(
    orgId: number,
    customerId: number,
    addressId: number,
    query: object,
  ) {
    return this.forward(
      orgId,
      'GET',
      `/customers/${customerId}/addresses/${addressId}.json`,
      undefined,
      query,
    );
  }

  createCustomerAddress(orgId: number, customerId: number, body: object) {
    return this.forward(
      orgId,
      'POST',
      `/customers/${customerId}/addresses.json`,
      body,
    );
  }

  updateCustomerAddress(
    orgId: number,
    customerId: number,
    addressId: number,
    body: object,
  ) {
    return this.forward(
      orgId,
      'PUT',
      `/customers/${customerId}/addresses/${addressId}.json`,
      body,
    );
  }

  deleteCustomerAddress(orgId: number, customerId: number, addressId: number) {
    return this.forward(
      orgId,
      'DELETE',
      `/customers/${customerId}/addresses/${addressId}.json`,
      {},
    );
  }

  setCustomerAddresses(orgId: number, customerId: number, body: object) {
    return this.forward(
      orgId,
      'PUT',
      `/customers/${customerId}/addresses/set.json`,
      body,
    );
  }

  setCustomerAddressDefault(
    orgId: number,
    customerId: number,
    addressId: number,
  ) {
    return this.forward(
      orgId,
      'PUT',
      `/customers/${customerId}/addresses/${addressId}/default.json`,
      {},
    );
  }

  listCountries(orgId: number, query: object) {
    return this.forward(orgId, 'GET', '/countries.json', undefined, query);
  }

  listProvinces(orgId: number, countryId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      `/countries/${countryId}/provinces.json`,
      undefined,
      query,
    );
  }

  listDistricts(orgId: number, provinceId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      `/provinces/${provinceId}/districts.json`,
      undefined,
      query,
    );
  }

  listWards(orgId: number, districtId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      `/districts/${districtId}/wards.json`,
      undefined,
      query,
    );
  }

  public async forward(
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
