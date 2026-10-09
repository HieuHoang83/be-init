import { Injectable } from '@nestjs/common';
import { ApiClient } from '../api/api.service';
import { HaravanGateway } from '../api/haravan.gateway';

/**
 * Service proxy tài nguyên Haravan của module haravan-location.
 * Mỗi module chỉ có các endpoint thuộc đúng tài nguyên của nó.
 */
@Injectable()
export class HaravanLocationService extends HaravanGateway {
  constructor(apiClient: ApiClient) {
    super(apiClient);
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
}
