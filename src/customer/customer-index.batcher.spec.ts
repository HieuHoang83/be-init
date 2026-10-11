import { JOB_NAMES } from '../queue/queue.service';
import { PendingBuffer, PendingOp } from '../elasticsearch/batch-buffer';
import { CustomerIndexBatcher } from './customer-index.batcher';

/**
 * Bo dem gia: giong het bo dem Redis ve han vi, nhung chi giu trong bo nho cua test.
 *
 * `failAdd` mo len se bao loi o `add` nhu Redis chap, dung de kiem tra duong chuyen sang hang doi
 * cong viec.
 */
class FakeBuffer implements PendingBuffer {
  readonly pending = new Map<string, PendingOp>();
  failAdd = false;
  drainCalls = 0;
  restoreCalls = 0;
  closed = false;
  onDue: (() => void) | null = null;

  async add(id: string, op: PendingOp): Promise<number> {
    if (this.failAdd) throw new Error('Redis khong ket noi duoc');
    this.pending.set(id, op);
    return this.pending.size;
  }

  async drain(): Promise<Array<[string, PendingOp]>> {
    this.drainCalls += 1;
    const batch = [...this.pending.entries()];
    this.pending.clear();
    return batch;
  }

  async restore(batch: Array<[string, PendingOp]>): Promise<void> {
    this.restoreCalls += 1;
    for (const [id, op] of batch) this.pending.set(id, op);
  }

  async size(): Promise<number> {
    return this.pending.size;
  }

  start(onDue: () => void): void {
    this.onDue = onDue;
  }

  stop(): void {
    this.onDue = null;
  }

  close(): void {
    this.closed = true;
  }
}

/**
 * Kiem tra hai dieu kien ghi index: du N khach thi ghi ngay, con it hon thi chi ghi khi het han.
 *
 * Bo dem thay the bang bo dem gia nen test khong phai co Redis; phan dung `RedisPendingBuffer` co
 * test rieng chay that voi Redis that.
 */
describe('CustomerIndexBatcher', () => {
  const cfg = {
    enabled: true,
    batchSize: 10,
    flushIntervalMs: 3000,
    maxPending: 2000,
    maxAttempts: 5,
  };

  let es: { isEnabled: jest.Mock; bulkDeleteCustomers: jest.Mock };
  let indexService: { syncCustomers: jest.Mock };
  let jobQueue: { enqueue: jest.Mock };
  let buffer: FakeBuffer;
  let batcher: CustomerIndexBatcher;

  beforeEach(() => {
    es = {
      isEnabled: jest.fn(() => true),
      bulkDeleteCustomers: jest.fn().mockResolvedValue(true),
    };
    indexService = {
      syncCustomers: jest.fn(async (ids: string[]) => ({
        failed: [],
        deleted: 0,
        indexed: ids.length,
      })),
    };
    jobQueue = { enqueue: jest.fn().mockResolvedValue({ id: 'job-1' }) };

    buffer = new FakeBuffer();

    class TestBatcher extends CustomerIndexBatcher {
      protected override createBuffer(): PendingBuffer {
        return buffer;
      }
    }

    batcher = new TestBatcher(
      cfg as never,
      es as never,
      indexService as never,
      jobQueue as never,
    );
    batcher.onModuleInit();
  });

  /** Cho moi loi han `await` ben trong `push()` chay het truoc khi kiem tra. */
  const settle = () => jest.advanceTimersByTimeAsync(0);

  it('ghi ngay khi du 10 khach, khong doi het han', async () => {
    for (let i = 0; i < 9; i += 1) batcher.enqueue(`c${i}`);
    await settle();
    expect(indexService.syncCustomers).not.toHaveBeenCalled();

    batcher.enqueue('c9');
    await settle();

    expect(indexService.syncCustomers).toHaveBeenCalledTimes(1);
    expect(indexService.syncCustomers.mock.calls[0][0]).toHaveLength(10);
  });

  it('it khach hon 10 thi chi ghi khi het han', async () => {
    batcher.enqueue('c1');
    batcher.enqueue('c2');
    await settle();

    expect(indexService.syncCustomers).not.toHaveBeenCalled();

    // Bo dem bao khi da het `flushIntervalMs` (với Redis là nhắc quét mỗi `batchTickMs`).
    buffer.onDue?.();
    await settle();

    expect(indexService.syncCustomers).toHaveBeenCalledTimes(1);
    expect(indexService.syncCustomers.mock.calls[0][0]).toEqual(['c1', 'c2']);
  });

  it('gom khach bi sua nhieu lan trong mot lo vao mot lan ghi', async () => {
    batcher.enqueue('c1');
    batcher.enqueue('c1');
    batcher.enqueue('c2');
    batcher.enqueue('c1');

    buffer.onDue?.();
    await settle();

    expect(indexService.syncCustomers.mock.calls[0][0]).toEqual(['c1', 'c2']);
  });

  it('thao tac sau thang theo truoc, nen khach bi xoa chi xoa mot lan', async () => {
    batcher.enqueue('c1');
    batcher.enqueueDelete('c1');
    batcher.enqueue('c2');

    buffer.onDue?.();
    await settle();

    expect(indexService.syncCustomers.mock.calls[0][0]).toEqual(['c2']);
    expect(es.bulkDeleteCustomers).toHaveBeenCalledWith(['c1']);
  });

  it('khong ghi gi khi Elasticsearch dang tat', async () => {
    es.isEnabled.mockReturnValue(false);
    batcher.enqueue('c1');
    buffer.onDue?.();
    await settle();

    expect(indexService.syncCustomers).not.toHaveBeenCalled();
  });

  it('chuyen phan chua sang hang doi khi bo dem tran', async () => {
    class TranBatcher extends CustomerIndexBatcher {
      protected override createBuffer(): PendingBuffer {
        return buffer;
      }
    }
    const tran = new TranBatcher(
      { ...cfg, maxPending: 3 } as never,
      es as never,
      indexService as never,
      jobQueue as never,
    );
    tran.onModuleInit();

    tran.enqueue('c1');
    tran.enqueue('c2');
    tran.enqueue('c3');
    await settle();

    expect(jobQueue.enqueue).toHaveBeenCalledWith(
      JOB_NAMES.CUSTOMER_ES_SYNC,
      { customerIds: ['c1', 'c2', 'c3'], deleteIds: [] },
      { maxAttempts: 10 },
    );
  });

  it('ghi khong duoc thi ghi lai bo dem de thu lai', async () => {
    indexService.syncCustomers.mockImplementation(async (ids: string[]) => ({
      failed: ids,
      deleted: 0,
      indexed: 0,
    }));

    batcher.enqueue('c1');
    buffer.onDue?.();
    await settle();

    expect(buffer.restoreCalls).toBe(1);
    expect(jobQueue.enqueue).not.toHaveBeenCalled();
  });

  it('thu lai het han thi day sang hang doi de khong ghi vo han', async () => {
    class HetBatcher extends CustomerIndexBatcher {
      protected override createBuffer(): PendingBuffer {
        return buffer;
      }
    }
    const het = new HetBatcher(
      { ...cfg, maxAttempts: 1 } as never,
      es as never,
      indexService as never,
      jobQueue as never,
    );
    het.onModuleInit();
    indexService.syncCustomers.mockImplementation(async (ids: string[]) => ({
      failed: ids,
      deleted: 0,
      indexed: 0,
    }));

    het.enqueue('c1');
    buffer.onDue?.();
    await settle();

    expect(buffer.restoreCalls).toBe(0);
    expect(jobQueue.enqueue).toHaveBeenCalledWith(
      JOB_NAMES.CUSTOMER_ES_SYNC,
      { customerIds: ['c1'], deleteIds: [] },
      { maxAttempts: 10 },
    );
  });

  it('lo gap loi (Mongo that bai) thi ghi lai bo dem, khong bo qua', async () => {
    indexService.syncCustomers.mockRejectedValue(
      new Error('MongooseServerSelectionError'),
    );

    batcher.enqueue('c1');
    batcher.enqueueDelete('c2');
    buffer.onDue?.();
    await settle();

    // Ca khach ghi va khach xoa deu quay lai bo dem. Retry luon di duong `index`: khi worker doc
    // lai Mongo se thay `c2` khong con nen tu dong xoa khoi index.
    expect(buffer.restoreCalls).toBe(1);
    expect([...buffer.pending.entries()]).toEqual([['c1', 'index'], ['c2', 'delete']]);
  });

  it('Redis chap thi day thang khach sang hang doi, khong chan ghi khach', async () => {
    buffer.failAdd = true;

    batcher.enqueue('c1');
    await settle();

    expect(jobQueue.enqueue).toHaveBeenCalledWith(
      JOB_NAMES.CUSTOMER_ES_SYNC,
      { customerIds: ['c1'], deleteIds: [] },
      { maxAttempts: 10 },
    );
  });

  it('dung tien trinh thi ghi ngan phan con lai truoc khi dong ket noi', async () => {
    batcher.enqueue('c1');
    batcher.enqueue('c2');
    await settle();

    await batcher.onModuleDestroy();

    expect(indexService.syncCustomers).toHaveBeenCalledWith(['c1', 'c2']);
    expect(buffer.closed).toBe(true);
  });
});
