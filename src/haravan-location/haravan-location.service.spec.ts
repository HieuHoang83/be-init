import { HaravanLocationService } from './haravan-location.service';
import { ApiClient } from '../api/api.service';

describe('HaravanLocationService', () => {
  const call = jest.fn();
  const apiClient = { call } as unknown as ApiClient;
  const service = new HaravanLocationService(apiClient);

  beforeEach(() => {
    call.mockReset();
    call.mockResolvedValue({
      body: { products: [] },
      statusCode: 200,
      durationMs: 1,
    });
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
});
