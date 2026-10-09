import { Injectable } from '@nestjs/common';
import { ApiClient } from '../api/api.service';
import { HaravanGateway } from '../api/haravan.gateway';

/**
 * Service proxy tài nguyên Haravan của module haravan-inventory.
 * Mỗi module chỉ có các endpoint thuộc đúng tài nguyên của nó.
 */
@Injectable()
export class HaravanInventoryService extends HaravanGateway {
  constructor(apiClient: ApiClient) {
    super(apiClient);
  }


  listInventoryLocations(orgId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      '/inventory_locations.json',
      undefined,
      query,
    );
  }

  /**
   * Chinh sua ton kho theo kho: POST /com/inventories/adjustorset.json.
   * Body: { inventory: { location_id, type: 'adjust' | 'set', reason, note,
   * line_items: [{ product_id, product_variant_id, quantity }] } }
   */
  adjustInventory(orgId: number, body: object) {
    return this.forward(orgId, 'POST', '/inventories/adjustorset.json', body);
  }

  listPurchaseReceives(orgId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      '/v2/inventories/purchase_receives.json',
      undefined,
      query,
    );
  }

  getPurchaseReceive(orgId: number, purchaseReceiveId: number) {
    return this.forward(
      orgId,
      'GET',
      `/v2/inventories/purchase_receives/${purchaseReceiveId}.json`,
    );
  }

  listPurchaseOrders(orgId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      '/inventories/purchase_orders.json',
      undefined,
      query,
    );
  }

  getPurchaseOrder(orgId: number, purchaseId: number) {
    return this.forward(
      orgId,
      'GET',
      `/inventories/purchase_orders/${purchaseId}.json`,
    );
  }

  listPurchaseReturns(orgId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      '/v2/inventories/purchase_returns.json',
      undefined,
      query,
    );
  }

  getPurchaseReturn(orgId: number, purchaseReturnId: number) {
    return this.forward(
      orgId,
      'GET',
      `/v2/inventories/purchase_returns/${purchaseReturnId}.json`,
    );
  }

  listInventoryTransfers(orgId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      '/inventories/transfers.json',
      undefined,
      query,
    );
  }

  countInventoryTransfers(orgId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      '/inventories/transfers/count.json',
      undefined,
      query,
    );
  }

  getInventoryTransfer(orgId: number, transferId: number) {
    return this.forward(
      orgId,
      'GET',
      `/inventorytransfer/detail/${transferId}.json`,
    );
  }

  createInventoryTransfer(orgId: number, body: object) {
    return this.forward(orgId, 'POST', '/inventories/transfer.json', body);
  }

  receiveInventoryTransfer(orgId: number, transferId: number, body: object) {
    return this.forward(
      orgId,
      'POST',
      `/inventories/transfer/${transferId}/receive.json`,
      body,
    );
  }

  listInventoryAdjustments(orgId: number, query: object) {
    return this.forward(
      orgId,
      'GET',
      '/inventories/adjustments.json',
      undefined,
      query,
    );
  }

  countInventoryAdjustments(orgId: number, query: object = {}) {
    return this.forward(
      orgId,
      'GET',
      '/inventories/adjustments/count.json',
      undefined,
      query,
    );
  }

  getInventoryAdjustment(orgId: number, adjustmentId: number) {
    return this.forward(
      orgId,
      'GET',
      `/inventories/adjustments/${adjustmentId}.json`,
    );
  }
}
