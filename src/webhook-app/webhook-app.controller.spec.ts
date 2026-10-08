import { WebhookAppController } from './webhook-app.controller';
import { ORDER_TOPIC_SET } from '../interface/order.interface';

describe('WebhookAppController - chi xu ly su kien don hang', () => {
  const record = jest.fn();
  const markStatus = jest.fn();
  const enqueue = jest.fn();

  const controller = new WebhookAppController(
    {} as never, // appService
    {} as never, // orderService
    { enqueue } as never,
    { record, markStatus } as never,
  );

  const ORG = '200001220496';

  function headers(topic: string, extra: Record<string, string> = {}) {
    return {
      'x-haravan-topic': topic,
      'x-haravan-org-id': ORG,
      ...extra,
    };
  }

  const req = { method: 'POST', originalUrl: '/webhooks/app', rawBody: null };

  beforeEach(() => {
    record.mockReset().mockResolvedValue({ _id: { toString: () => 'evt-1' } });
    markStatus.mockReset().mockResolvedValue(undefined);
    enqueue.mockReset().mockResolvedValue({ id: 'job-1' });
  });

  it('day vao hang doi voi tung su kien don hang', async () => {
    for (const topic of [...ORDER_TOPIC_SET]) {
      const result = await controller.receive(
        { id: 123, name: '#10001', total_price: '1000' },
        headers(topic),
        req as never,
      );

      expect(result.queued).toBe(true);
    }
    expect(enqueue).toHaveBeenCalledTimes(ORDER_TOPIC_SET.size);
  });

  it('bo qua cac topic khong lien quan don hang', async () => {
    const unrelated = [
      'customers/update',
      'customers/create',
      'products/update',
      'products/deleted',
      'locations/create',
      'locations/delete',
      'inventorytransaction/create',
      'inventorylocationbalances/update',
      'shop/update',
      'app/uninstalled',
      'unknown',
    ];

    for (const topic of unrelated) {
      // `id` ở đây là ID khách/sản phẩm/kho, KHÔNG phải ID đơn.
      const result = await controller.receive(
        { id: 1176354931, email: 'kh@example.com' },
        headers(topic),
        req as never,
      );

      expect(result.queued).toBe(false);
    }

    expect(enqueue).not.toHaveBeenCalled();
    expect(record).not.toHaveBeenCalled();
  });

  it('bo qua payload kiem tra cua Haravan', async () => {
    const result = await controller.receive(
      { id: 123, name: '#10001' },
      headers('orders/create', { 'x-haravan-test': 'true' }),
      req as never,
    );

    expect(result.queued).toBe(false);
    expect(enqueue).not.toHaveBeenCalled();
  });

  it('van tra 200 de Haravan khong goi lai lien tuc', async () => {
    const result = await controller.receive(
      { id: 123 },
      headers('customers/update'),
      req as never,
    );

    expect(result.received).toBe(true);
  });

  it('van enqueue don thieu truong de worker fallback goi Haravan API', async () => {
    const result = await controller.receive(
      { id: 42 },
      headers('orders/create'),
      req as never,
    );

    // Body thiếu trường đơn hàng -> ghi nhận để xử lý lại từ API, vẫn enqueue.
    expect(result.queued).toBe(true);
  });
});
