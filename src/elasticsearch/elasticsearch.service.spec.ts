import { ElasticsearchService } from './elasticsearch.service';

/**
 * Kiem tra cach danh gia ket qua `bulk`: ban cu hon ban dang co san trong index khong phai loi,
 * con mapping sai thi phai bao loi that va tra `false` de hang doi cong viec thu lai.
 */
describe('ElasticsearchService.bulkIndexCustomers', () => {
  const cfg = {
    enabled: true,
    node: 'http://localhost:9200',
    indexPrefix: 'haravan',
    requestTimeoutMs: 5000,
    maxRetries: 0,
  };

  let bulk: jest.Mock;
  let service: ElasticsearchService;

  beforeEach(() => {
    bulk = jest.fn();
    service = new ElasticsearchService(cfg as never);

    // Thay client ES that bang mock va danh dau index san sang, nho do khong goi network.
    Object.defineProperty(service, 'getClient', {
      value: () => ({ bulk }),
    });
    Object.defineProperty(service, 'indexReady', { value: true, writable: true });
  });

  it('ban cu hon ban moi hon trong index thi bo qua, khong coi la loi', async () => {
    bulk.mockResolvedValue({
      errors: true,
      items: [
        {
          index: {
            status: 409,
            error: {
              type: 'version_conflict_engine_exception',
              reason: 'current version is newer',
            },
          },
        },
      ],
    });

    await expect(
      service.bulkIndexCustomers([{ id: 'c1', syncedAt: 1 }], ['c1']),
    ).resolves.toBe(true);
  });

  it('mapping sai thi tra false de hang doi cong viec thu lai', async () => {
    bulk.mockResolvedValue({
      errors: true,
      items: [
        {
          index: {
            status: 400,
            error: { type: 'mapper_parsing_exception', reason: 'failed to parse' },
          },
        },
      ],
    });

    await expect(
      service.bulkIndexCustomers([{ id: 'c1', syncedAt: 1 }], ['c1']),
    ).resolves.toBe(false);
  });
});
