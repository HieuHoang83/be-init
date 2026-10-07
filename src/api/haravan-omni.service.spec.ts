import { HaravanOmniService } from './haravan-omni.service';
import { ApiClient } from './api.service';

describe('HaravanOmniService', () => {
  const call = jest.fn();
  const service = new HaravanOmniService({ call } as unknown as ApiClient);

  beforeEach(() => {
    call.mockReset();
    call.mockResolvedValue({
      body: { products: [] },
      statusCode: 200,
      durationMs: 1,
    });
  });

  it('listProducts goi GET /products.json kem filter Haravan', async () => {
    await service.listProducts(200001220496, {
      page: '1',
      ids: '1033237384,1033237559',
      vendor: 'Burton',
    });

    expect(call).toHaveBeenCalledWith(
      200001220496,
      'GET',
      '/products.json',
      undefined,
      { page: '1', ids: '1033237384,1033237559', vendor: 'Burton' },
    );
  });

  it('createProduct goi POST /products.json voi body { product }', async () => {
    call.mockResolvedValue({
      body: { product: { id: 1 } },
      statusCode: 201,
      durationMs: 1,
    });
    const body = {
      product: { title: 'Burton Custom Freestyle 151', vendor: 'Burton' },
    };

    await expect(service.createProduct(1, body)).resolves.toEqual({
      product: { id: 1 },
    });
    expect(call).toHaveBeenCalledWith(
      1,
      'POST',
      '/products.json',
      body,
      undefined,
    );
  });

  it('addProductTags goi POST /products/{id}/tags.json', async () => {
    call.mockResolvedValue({
      body: { tags: 'a1,a2' },
      statusCode: 200,
      durationMs: 1,
    });
    await service.addProductTags(1, 1050764416, { tags: 'a1,a2' });
    expect(call).toHaveBeenCalledWith(
      1,
      'POST',
      '/products/1050764416/tags.json',
      { tags: 'a1,a2' },
      undefined,
    );
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

  it('listProductVariants goi GET /products/{id}/variants.json', async () => {
    call.mockResolvedValue({
      body: { variants: [] },
      statusCode: 200,
      durationMs: 1,
    });
    await service.listProductVariants(1, 1034037268, { page: '1' });
    expect(call).toHaveBeenCalledWith(
      1,
      'GET',
      '/products/1034037268/variants.json',
      undefined,
      { page: '1' },
    );
  });

  it('countProductVariants goi GET /products/{id}/variants/count.json', async () => {
    call.mockResolvedValue({
      body: { count: 2 },
      statusCode: 200,
      durationMs: 1,
    });
    await service.countProductVariants(1, 1034037268, {});
    expect(call).toHaveBeenCalledWith(
      1,
      'GET',
      '/products/1034037268/variants/count.json',
      undefined,
      {},
    );
  });

  it('getVariant goi GET /variants/{id}.json', async () => {
    call.mockResolvedValue({
      body: { variant: { id: 1 } },
      statusCode: 200,
      durationMs: 1,
    });
    await service.getVariant(1, 1075012798, { fields: 'sku,price' });
    expect(call).toHaveBeenCalledWith(
      1,
      'GET',
      '/variants/1075012798.json',
      undefined,
      { fields: 'sku,price' },
    );
  });

  it('createProductVariant goi POST /products/{id}/variants.json', async () => {
    const body = { variant: { sku: 'CSSWWW', option1: 'S', price: 100000 } };
    call.mockResolvedValue({
      body: { variant: { id: 2 } },
      statusCode: 201,
      durationMs: 1,
    });
    await expect(
      service.createProductVariant(1, 1034037268, body),
    ).resolves.toEqual({
      variant: { id: 2 },
    });
    expect(call).toHaveBeenCalledWith(
      1,
      'POST',
      '/products/1034037268/variants.json',
      body,
      undefined,
    );
  });

  it('updateProductVariant goi PUT /variants/{id}.json', async () => {
    const body = { variant: { id: 1077703228, price: 200000 } };
    call.mockResolvedValue({
      body: { variant: { id: 1077703228 } },
      statusCode: 200,
      durationMs: 1,
    });
    await service.updateProductVariant(1, 1077703228, body);
    expect(call).toHaveBeenCalledWith(
      1,
      'PUT',
      '/variants/1077703228.json',
      body,
      undefined,
    );
  });

  it('deleteProductVariant goi DELETE /products/{id}/variants/{variantId}.json rong body', async () => {
    call.mockResolvedValue({ body: {}, statusCode: 200, durationMs: 1 });
    await service.deleteProductVariant(1, 1034037268, 1077703228);
    expect(call).toHaveBeenCalledWith(
      1,
      'DELETE',
      '/products/1034037268/variants/1077703228.json',
      {},
      undefined,
    );
  });

  it('listLocations goi GET /locations.json', async () => {
    call.mockResolvedValue({
      body: { locations: [] },
      statusCode: 200,
      durationMs: 1,
    });
    await service.listLocations(1, { page: '1' });
    expect(call).toHaveBeenCalledWith(1, 'GET', '/locations.json', undefined, {
      page: '1',
    });
  });

  it('getLocation goi GET /locations/{id}.json', async () => {
    call.mockResolvedValue({
      body: { location: { id: 224543 } },
      statusCode: 200,
      durationMs: 1,
    });
    await service.getLocation(1, 224543, {});
    expect(call).toHaveBeenCalledWith(
      1,
      'GET',
      '/locations/224543.json',
      undefined,
      {},
    );
  });

  it('listInventoryLocations goi GET /inventory_locations.json kem location_ids/variant_ids', async () => {
    call.mockResolvedValue({
      body: { inventory_locations: [] },
      statusCode: 200,
      durationMs: 1,
    });
    await service.listInventoryLocations(1, {
      location_ids: '224543',
      variant_ids: '1077703228',
    });
    expect(call).toHaveBeenCalledWith(
      1,
      'GET',
      '/inventory_locations.json',
      undefined,
      { location_ids: '224543', variant_ids: '1077703228' },
    );
  });

  it('adjustInventory goi POST /inventories/adjustorset.json', async () => {
    call.mockResolvedValue({
      body: { ok: true },
      statusCode: 200,
      durationMs: 1,
    });
    const body = {
      inventory: {
        location_id: 224543,
        type: 'set',
        reason: 'newproduct',
        line_items: [
          {
            product_id: 1034037268,
            product_variant_id: 1077703228,
            quantity: 12,
          },
        ],
      },
    };
    await expect(service.adjustInventory(1, body)).resolves.toEqual({
      ok: true,
    });
    expect(call).toHaveBeenCalledWith(
      1,
      'POST',
      '/inventories/adjustorset.json',
      body,
      undefined,
    );
  });

  it('listCollections goi GET /custom_collections.json', async () => {
    call.mockResolvedValue({
      body: { collections: [] },
      statusCode: 200,
      durationMs: 1,
    });
    await service.listCollections(1, { page: '1', title: 'Summer' });
    expect(call).toHaveBeenCalledWith(
      1,
      'GET',
      '/custom_collections.json',
      undefined,
      { page: '1', title: 'Summer' },
    );
  });

  it('countCollections goi GET /custom_collections/count.json', async () => {
    call.mockResolvedValue({
      body: { count: 3 },
      statusCode: 200,
      durationMs: 1,
    });
    await service.countCollections(1, { handle: 'frontpage' });
    expect(call).toHaveBeenCalledWith(
      1,
      'GET',
      '/custom_collections/count.json',
      undefined,
      { handle: 'frontpage' },
    );
  });

  it('getCollection goi GET /custom_collections/{id}.json', async () => {
    call.mockResolvedValue({
      body: { collection: { id: 841564295 } },
      statusCode: 200,
      durationMs: 1,
    });
    await service.getCollection(1, 841564295, { fields: 'title,handle' });
    expect(call).toHaveBeenCalledWith(
      1,
      'GET',
      '/custom_collections/841564295.json',
      undefined,
      { fields: 'title,handle' },
    );
  });

  it('createCollection goi POST /custom_collections.json', async () => {
    const body = { collection: { title: 'Summer' } };
    call.mockResolvedValue({
      body: { collection: { id: 1 } },
      statusCode: 201,
      durationMs: 1,
    });
    await expect(service.createCollection(1, body)).resolves.toEqual({
      collection: { id: 1 },
    });
    expect(call).toHaveBeenCalledWith(
      1,
      'POST',
      '/custom_collections.json',
      body,
      undefined,
    );
  });

  it('updateCollection goi PUT /custom_collections/{id}.json', async () => {
    const body = { collection: { id: 841564295, title: 'Summer 2' } };
    call.mockResolvedValue({
      body: { collection: { id: 841564295 } },
      statusCode: 200,
      durationMs: 1,
    });
    await service.updateCollection(1, 841564295, body);
    expect(call).toHaveBeenCalledWith(
      1,
      'PUT',
      '/custom_collections/841564295.json',
      body,
      undefined,
    );
  });

  it('deleteCollection goi DELETE /custom_collections/{id}.json rong body', async () => {
    call.mockResolvedValue({ body: {}, statusCode: 200, durationMs: 1 });
    await service.deleteCollection(1, 841564295);
    expect(call).toHaveBeenCalledWith(
      1,
      'DELETE',
      '/custom_collections/841564295.json',
      {},
      undefined,
    );
  });

  it('listCollects goi GET /collects.json kem product_id/collection_id', async () => {
    call.mockResolvedValue({
      body: { collects: [] },
      statusCode: 200,
      durationMs: 1,
    });
    await service.listCollects(1, { product_id: '1076990203' });
    expect(call).toHaveBeenCalledWith(1, 'GET', '/collects.json', undefined, {
      product_id: '1076990203',
    });
  });

  it('countCollects goi GET /collects/count.json', async () => {
    call.mockResolvedValue({
      body: { count: 2 },
      statusCode: 200,
      durationMs: 1,
    });
    await service.countCollects(1, { collection_id: '841564295' });
    expect(call).toHaveBeenCalledWith(
      1,
      'GET',
      '/collects/count.json',
      undefined,
      { collection_id: '841564295' },
    );
  });

  it('getCollect goi GET /collects/{id}.json', async () => {
    call.mockResolvedValue({
      body: { collect: { id: 9 } },
      statusCode: 200,
      durationMs: 1,
    });
    await service.getCollect(1, 9, {});
    expect(call).toHaveBeenCalledWith(
      1,
      'GET',
      '/collects/9.json',
      undefined,
      {},
    );
  });

  it('createCollect goi POST /collects.json', async () => {
    const body = {
      collect: { product_id: 1076990203, collection_id: 841564295 },
    };
    call.mockResolvedValue({
      body: { collect: { id: 9 } },
      statusCode: 201,
      durationMs: 1,
    });
    await expect(service.createCollect(1, body)).resolves.toEqual({
      collect: { id: 9 },
    });
    expect(call).toHaveBeenCalledWith(
      1,
      'POST',
      '/collects.json',
      body,
      undefined,
    );
  });

  it('deleteCollect goi DELETE /collects/{id}.json rong body', async () => {
    call.mockResolvedValue({ body: {}, statusCode: 200, durationMs: 1 });
    await service.deleteCollect(1, 9);
    expect(call).toHaveBeenCalledWith(
      1,
      'DELETE',
      '/collects/9.json',
      {},
      undefined,
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

  it('listCountries goi GET /countries.json', async () => {
    call.mockResolvedValue({
      body: { countries: [] },
      statusCode: 200,
      durationMs: 1,
    });
    await service.listCountries(1, {});
    expect(call).toHaveBeenCalledWith(
      1,
      'GET',
      '/countries.json',
      undefined,
      {},
    );
  });

  it('listProvinces goi GET /countries/{id}/provinces.json', async () => {
    call.mockResolvedValue({
      body: { provinces: [] },
      statusCode: 200,
      durationMs: 1,
    });
    await service.listProvinces(1, 241, { limit: '100' });
    expect(call).toHaveBeenCalledWith(
      1,
      'GET',
      '/countries/241/provinces.json',
      undefined,
      { limit: '100' },
    );
  });

  it('listDistricts goi GET /provinces/{id}/districts.json', async () => {
    call.mockResolvedValue({
      body: { districts: [] },
      statusCode: 200,
      durationMs: 1,
    });
    await service.listDistricts(1, 1079, {});
    expect(call).toHaveBeenCalledWith(
      1,
      'GET',
      '/provinces/1079/districts.json',
      undefined,
      {},
    );
  });

  it('listWards goi GET /districts/{id}/wards.json', async () => {
    call.mockResolvedValue({
      body: { wards: [] },
      statusCode: 200,
      durationMs: 1,
    });
    await service.listWards(1, 1027226, {});
    expect(call).toHaveBeenCalledWith(
      1,
      'GET',
      '/districts/1027226/wards.json',
      undefined,
      {},
    );
  });
});
