import { HaravanProductService } from './haravan-product.service';
import { ApiClient } from '../api/api.service';

describe('HaravanProductService', () => {
  const call = jest.fn();
  const apiClient = { call } as unknown as ApiClient;
  const service = new HaravanProductService(apiClient);

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
});
