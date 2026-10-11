import { WebhookAppController } from './webhook-app.controller';
import {
  CUSTOMER_TOPIC_SET,
  ORDER_TOPIC_SET,
} from '../../interface/order.interface';
import { JOB_NAMES } from '../../queue/queue.service';

describe('WebhookAppController - don hang va khach hang', () => {
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
  /** Id khach tren Haravan; khac `id` cua don hang, dung de kiem tra ho nham khach. */
  const CUSTOMER_ID = 1176354931;

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

  describe('don hang', () => {
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

    it('bo qua payload kiem tra cua Haravan', async () => {
      const result = await controller.receive(
        { id: 123, name: '#10001' },
        headers('orders/create', { 'x-haravan-test': 'true' }),
        req as never,
      );

      expect(result.queued).toBe(false);
      expect(enqueue).not.toHaveBeenCalled();
    });

    it('van enqueue don thieu truong de worker fallback goi Haravan API', async () => {
      const result = await controller.receive(
        { id: 42 },
        headers('orders/create'),
        req as never,
      );

      // Body thieu truong don hang -> ghi nhan de xu ly lai tu API, van enqueue.
      expect(result.queued).toBe(true);
    });
  });

  describe('khach hang', () => {
    it('day vao hang dong bo khach cho moi topic khach hang', async () => {
      for (const topic of [...CUSTOMER_TOPIC_SET]) {
        const result = await controller.receive(
          { customer: { id: CUSTOMER_ID, email: 'kh@example.com' } },
          headers(topic),
          req as never,
        );

        expect(result.queued).toBe(true);
        expect(enqueue).toHaveBeenLastCalledWith(
          JOB_NAMES.CUSTOMER_WEBHOOK_SYNC,
          {
            orgId: Number(ORG),
            topic,
            customer: { id: CUSTOMER_ID, email: 'kh@example.com' },
          },
        );
      }

      expect(enqueue).toHaveBeenCalledTimes(CUSTOMER_TOPIC_SET.size);
      expect(record).not.toHaveBeenCalled();
    });

    it('nhan duoc ca khi body phang, khong boc trong `customer`', async () => {
      const result = await controller.receive(
        { id: CUSTOMER_ID, email: 'kh@example.com' },
        headers('customers/update'),
        req as never,
      );

      expect(result.queued).toBe(true);
      expect(enqueue).toHaveBeenCalledWith(
        JOB_NAMES.CUSTOMER_WEBHOOK_SYNC,
        {
          orgId: Number(ORG),
          topic: 'customers/update',
          customer: { id: CUSTOMER_ID, email: 'kh@example.com' },
        },
      );
    });

    it('khong co `customer.id` thi bo qua, vi khong dinh danh duoc khach', async () => {
      const result = await controller.receive(
        { email: 'kh@example.com' },
        headers('customers/create'),
        req as never,
      );

      expect(result.queued).toBe(false);
      expect(result.received).toBe(true);
      expect(enqueue).not.toHaveBeenCalled();
    });

    it('khong co org id thi bo qua', async () => {
      const result = await controller.receive(
        { id: CUSTOMER_ID },
        { 'x-haravan-topic': 'customers/create' },
        req as never,
      );

      expect(result.queued).toBe(false);
      expect(enqueue).not.toHaveBeenCalled();
    });

    it('bo qua payload kiem tra cua Haravan', async () => {
      const result = await controller.receive(
        { id: CUSTOMER_ID },
        headers('customers/update', { 'x-haravan-test': 'true' }),
        req as never,
      );

      expect(result.queued).toBe(false);
      expect(enqueue).not.toHaveBeenCalled();
    });
  });

  describe('topic khong lien quan', () => {
    it('bo qua ma khong ghi gi ca', async () => {
      const unrelated = [
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
        // `id` o day la ID khach/san pham/kho, KHONG phai ID don.
        const result = await controller.receive(
          { id: CUSTOMER_ID, email: 'kh@example.com' },
          headers(topic),
          req as never,
        );

        expect(result.queued).toBe(false);
      }

      expect(enqueue).not.toHaveBeenCalled();
      expect(record).not.toHaveBeenCalled();
    });

    it('van tra 200 de Haravan khong goi lai lien tuc', async () => {
      const result = await controller.receive(
        { id: 123 },
        headers('unknown'),
        req as never,
      );

      expect(result.received).toBe(true);
    });
  });
});
