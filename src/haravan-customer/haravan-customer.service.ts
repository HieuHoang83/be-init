import { Injectable } from '@nestjs/common';
import { ApiClient } from '../api/api.service';
import { HaravanGateway } from '../api/haravan.gateway';

/**
 * Haravan viet API theo kieu Rails: thanh body phai nam trong truong `customer`.
 *
 * Gui body phang se nhan `400 customer must be an object`. Ham nay boc san cho moi thao tac
 * tao/sua khach; neu caller da boc thi giup nguyen de khong boc hai lan.
 */
function wrapCustomer(body: object): object {
  if (body && typeof body === 'object' && 'customer' in body) return body;
  return { customer: body };
}

/**
 * Service proxy tài nguyên Haravan của module haravan-customer.
 * Mỗi module chỉ có các endpoint thuộc đúng tài nguyên của nó.
 */
@Injectable()
export class HaravanCustomerService extends HaravanGateway {
  constructor(apiClient: ApiClient) {
    super(apiClient);
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
    return this.forward(orgId, 'POST', '/customers.json', wrapCustomer(body));
  }

  updateCustomer(orgId: number, customerId: number, body: object) {
    return this.forward(
      orgId,
      'PUT',
      `/customers/${customerId}.json`,
      wrapCustomer(body),
    );
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
}
