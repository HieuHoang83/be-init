import { HaravanInventoryService } from './haravan-inventory.service';
import { ApiClient } from '../api/api.service';

describe('HaravanInventoryService', () => {
  const call = jest.fn();
  const apiClient = { call } as unknown as ApiClient;
  const service = new HaravanInventoryService(apiClient);

  beforeEach(() => {
    call.mockReset();
    call.mockResolvedValue({
      body: { products: [] },
      statusCode: 200,
      durationMs: 1,
    });
  });

    it('listInventoryLocations goi GET /inventory_locations.json kem location_ids/variant_ids', async () => {
      call.mockResolvedValue({
        body: { inventory_locations: [] },
        statusCode: 200,
        durationMs: 1,
      });
      await service.listInventoryLocations(1, {
        location_ids: '224543',
        variant_ids: '1077703228',
      });
      expect(call).toHaveBeenCalledWith(
        1,
        'GET',
        '/inventory_locations.json',
        undefined,
        { location_ids: '224543', variant_ids: '1077703228' },
      );
    });

    it('adjustInventory goi POST /inventories/adjustorset.json', async () => {
      call.mockResolvedValue({
        body: { ok: true },
        statusCode: 200,
        durationMs: 1,
      });
      const body = {
        inventory: {
          location_id: 224543,
          type: 'set',
          reason: 'newproduct',
          line_items: [
            {
              product_id: 1034037268,
              product_variant_id: 1077703228,
              quantity: 12,
            },
          ],
        },
      };
      await expect(service.adjustInventory(1, body)).resolves.toEqual({
        ok: true,
      });
      expect(call).toHaveBeenCalledWith(
        1,
        'POST',
        '/inventories/adjustorset.json',
        body,
        undefined,
      );
    });
});
