import { HaravanGeoService } from './haravan-geo.service';
import { ApiClient } from '../api/api.service';

describe('HaravanGeoService', () => {
  const call = jest.fn();
  const apiClient = { call } as unknown as ApiClient;
  const service = new HaravanGeoService(apiClient);

  beforeEach(() => {
    call.mockReset();
    call.mockResolvedValue({
      body: { products: [] },
      statusCode: 200,
      durationMs: 1,
    });
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
