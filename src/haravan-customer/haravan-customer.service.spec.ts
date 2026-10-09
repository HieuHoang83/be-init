import { HaravanCustomerService } from './haravan-customer.service';
import { ApiClient } from '../api/api.service';

describe('HaravanCustomerService', () => {
  const call = jest.fn();
  const apiClient = { call } as unknown as ApiClient;
  const service = new HaravanCustomerService(apiClient);

  beforeEach(() => {
    call.mockReset();
    call.mockResolvedValue({
      body: { products: [] },
      statusCode: 200,
      durationMs: 1,
    });
  });

    it('searchCustomers goi GET /customers/search.json', async () => {
      call.mockResolvedValue({
        body: { customers: [] },
        statusCode: 200,
        durationMs: 1,
      });
      await service.searchCustomers(9, { query: 'haravan' });
      expect(call).toHaveBeenCalledWith(
        9,
        'GET',
        '/customers/search.json',
        undefined,
        { query: 'haravan' },
      );
    });

    it('listCustomerAddresses goi GET /customers/{id}/addresses.json', async () => {
      call.mockResolvedValue({
        body: { addresses: [] },
        statusCode: 200,
        durationMs: 1,
      });
      await service.listCustomerAddresses(1, 207119551, { page: '1' });
      expect(call).toHaveBeenCalledWith(
        1,
        'GET',
        '/customers/207119551/addresses.json',
        undefined,
        { page: '1' },
      );
    });

    it('getCustomerAddress goi GET /customers/{id}/addresses/{addressId}.json', async () => {
      call.mockResolvedValue({
        body: { address: { id: 1053317287 } },
        statusCode: 200,
        durationMs: 1,
      });
      await service.getCustomerAddress(1, 207119551, 1053317287, {});
      expect(call).toHaveBeenCalledWith(
        1,
        'GET',
        '/customers/207119551/addresses/1053317287.json',
        undefined,
        {},
      );
    });

    it('createCustomerAddress goi POST /customers/{id}/addresses.json', async () => {
      const body = { address: { address1: '182 Lê Đại Hành' } };
      call.mockResolvedValue({
        body: { address: { id: 1 } },
        statusCode: 201,
        durationMs: 1,
      });
      await expect(
        service.createCustomerAddress(1, 1172044253, body),
      ).resolves.toEqual({ address: { id: 1 } });
      expect(call).toHaveBeenCalledWith(
        1,
        'POST',
        '/customers/1172044253/addresses.json',
        body,
        undefined,
      );
    });

    it('updateCustomerAddress goi PUT /customers/{id}/addresses/{addressId}.json', async () => {
      const body = { address: { id: 207119551, zip: 'H0H 0H0' } };
      call.mockResolvedValue({
        body: { address: { id: 207119551 } },
        statusCode: 200,
        durationMs: 1,
      });
      await service.updateCustomerAddress(1, 207119551, 207119551, body);
      expect(call).toHaveBeenCalledWith(
        1,
        'PUT',
        '/customers/207119551/addresses/207119551.json',
        body,
        undefined,
      );
    });

    it('deleteCustomerAddress goi DELETE /customers/{id}/addresses/{addressId}.json rong body', async () => {
      call.mockResolvedValue({ body: {}, statusCode: 200, durationMs: 1 });
      await service.deleteCustomerAddress(1, 1172044253, 1053317288);
      expect(call).toHaveBeenCalledWith(
        1,
        'DELETE',
        '/customers/1172044253/addresses/1053317288.json',
        {},
        undefined,
      );
    });

    it('setCustomerAddresses goi PUT /customers/{id}/addresses/set.json', async () => {
      const body = { addresses: [{ id: 1, default: true }] };
      call.mockResolvedValue({ body: {}, statusCode: 200, durationMs: 1 });
      await service.setCustomerAddresses(1, 1172044253, body);
      expect(call).toHaveBeenCalledWith(
        1,
        'PUT',
        '/customers/1172044253/addresses/set.json',
        body,
        undefined,
      );
    });

    it('setCustomerAddressDefault goi PUT /customers/{id}/addresses/{addressId}/default.json', async () => {
      call.mockResolvedValue({
        body: { address: { id: 1053317287 } },
        statusCode: 200,
        durationMs: 1,
      });
      await service.setCustomerAddressDefault(1, 207119551, 1053317287);
      expect(call).toHaveBeenCalledWith(
        1,
        'PUT',
        '/customers/207119551/addresses/1053317287/default.json',
        {},
        undefined,
      );
    });
});
