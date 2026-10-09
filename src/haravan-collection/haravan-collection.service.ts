import { Injectable } from '@nestjs/common';
import { ApiClient } from '../api/api.service';
import { HaravanGateway } from '../api/haravan.gateway';

/**
 * Service proxy tài nguyên Haravan của module haravan-collection.
 * Mỗi module chỉ có các endpoint thuộc đúng tài nguyên của nó.
 */
@Injectable()
export class HaravanCollectionService extends HaravanGateway {
  constructor(apiClient: ApiClient) {
    super(apiClient);
  }


  listCollections(orgId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      '/custom_collections.json',
      undefined,
      query,
    );
  }

  countCollections(orgId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      '/custom_collections/count.json',
      undefined,
      query,
    );
  }

  getCollection(orgId: number, collectionId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      `/custom_collections/${collectionId}.json`,
      undefined,
      query,
    );
  }

  createCollection(orgId: number, body: object) {
    return this.forward(orgId, 'POST', '/custom_collections.json', body);
  }

  updateCollection(orgId: number, collectionId: number, body: object) {
    return this.forward(
      orgId,
      'PUT',
      `/custom_collections/${collectionId}.json`,
      body,
    );
  }

  deleteCollection(orgId: number, collectionId: number) {
    return this.forward(
      orgId,
      'DELETE',
      `/custom_collections/${collectionId}.json`,
      {},
    );
  }

}

