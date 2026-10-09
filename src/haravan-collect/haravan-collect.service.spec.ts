import { HaravanCollectService } from './haravan-collect.service';
import { ApiClient } from '../api/api.service';

describe('HaravanCollectService', () => {
  const call = jest.fn();
  const apiClient = { call } as unknown as ApiClient;
  const service = new HaravanCollectService(apiClient);

  beforeEach(() => {
    call.mockReset();
    call.mockResolvedValue({
      body: { products: [] },
      statusCode: 200,
      durationMs: 1,
    });
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
});
