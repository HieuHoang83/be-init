import { HaravanCollectionService } from './haravan-collection.service';
import { ApiClient } from '../api/api.service';

describe('HaravanCollectionService', () => {
  const call = jest.fn();
  const apiClient = { call } as unknown as ApiClient;
  const service = new HaravanCollectionService(apiClient);

  beforeEach(() => {
    call.mockReset();
    call.mockResolvedValue({
      body: { products: [] },
      statusCode: 200,
      durationMs: 1,
    });
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
});
