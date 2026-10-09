import { Injectable } from '@nestjs/common';
import { ApiClient } from '../api/api.service';
import { HaravanGateway } from '../api/haravan.gateway';

/**
 * Service proxy tài nguyên Haravan của module haravan-collect.
 * Mỗi module chỉ có các endpoint thuộc đúng tài nguyên của nó.
 */
@Injectable()
export class HaravanCollectService extends HaravanGateway {
  constructor(apiClient: ApiClient) {
    super(apiClient);
  }

  listCollects(orgId: number, query: object) {
    return this.forward(orgId, 'GET', '/collects.json', undefined, query);
  }

  countCollects(orgId: number, query: object) {
    return this.forward(orgId, 'GET', '/collects/count.json', undefined, query);
  }

  getCollect(orgId: number, collectId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      `/collects/${collectId}.json`,
      undefined,
      query,
    );
  }

  createCollect(orgId: number, body: object) {
    return this.forward(orgId, 'POST', '/collects.json', body);
  }

  deleteCollect(orgId: number, collectId: number) {
    return this.forward(orgId, 'DELETE', `/collects/${collectId}.json`, {});
  }
}

