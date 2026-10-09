import { Injectable } from '@nestjs/common';
import { ApiClient } from '../api/api.service';
import { HaravanGateway } from '../api/haravan.gateway';

/**
 * Service proxy tài nguyên Haravan của module haravan-geo.
 * Mỗi module chỉ có các endpoint thuộc đúng tài nguyên của nó.
 */
@Injectable()
export class HaravanGeoService extends HaravanGateway {
  constructor(apiClient: ApiClient) {
    super(apiClient);
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
}
