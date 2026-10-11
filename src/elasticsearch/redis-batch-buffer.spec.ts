import Redis from 'ioredis';
import { RedisPendingBuffer } from './redis-batch-buffer';
import { ElasticsearchConfig } from './elasticsearch.config';

/**
 * Kiem tra bo dem Redis that voi mot instance Redis that.
 *
 * Cac script Lua la phan quan trong nhat cua bo dem nen test o day dung chay lenh that chu khong
 * gia lap. Khi khong co Redis (may khac, CI) test bo qua thay vi lam do that hong.
 */
describe('RedisPendingBuffer', () => {
  const url = process.env.ELASTICSEARCH_REDIS_URL || 'redis://127.0.0.1:6379';
  // Tien to rieng cho test de khong lam anh huong du lieu chay that.
  const prefix = `test:es:${Date.now()}`;

  const cfg = {
    redisUrl: url,
    redisKeyPrefix: prefix,
    batchSize: 10,
    flushIntervalMs: 300,
    batchTickMs: 50,
    maxPending: 2000,
    maxAttempts: 5,
  } as unknown as ElasticsearchConfig;

  let redis: Redis | null = null;
  let available = false;
  let buffer: RedisPendingBuffer;

  const pendingKey = `${prefix}:es:pending`;
  const processingPrefix = `${prefix}:es:processing:`;

  beforeAll(async () => {
    const probe = new Redis(url, {
      connectTimeout: 1000,
      maxRetriesPerRequest: 1,
      retryStrategy: () => null,
    });
    try {
      await probe.ping();
      available = true;
      redis = probe;
    } catch {
      available = false;
      probe.disconnect();
    }
  });

  afterAll(async () => {
    if (redis) {
      const keys = await redis.keys(`${prefix}*`);
      if (keys.length) await redis.del(...keys);
      redis.disconnect();
    }
  });

  beforeEach(async () => {
    if (!available || !redis) return;
    const keys = await redis.keys(`${prefix}*`);
    if (keys.length) await redis.del(...keys);
    buffer = new RedisPendingBuffer(redis as Redis, cfg as never);
  });

  const moi = (id: string, op: 'index' | 'delete') => buffer.add(id, op);

  it('cung mot khach nhieu lan chi con mot muc', async () => {
    await moi('c1', 'index');
    await moi('c1', 'index');
    const size = await moi('c2', 'index');
    if (!available) return;

    expect(size).toBe(2);
    expect(await buffer.size()).toBe(2);
  });

  it('thao tac sau ghi de thao tac truoc: sua roi xoa ra xoa', async () => {
    await moi('c1', 'index');
    await moi('c1', 'delete');

    expect(await buffer.drain()).toEqual([['c1', 'delete']]);
  });

  it('rut lo lay ra het khach va khong con lai gi trong bo dem', async () => {
    await moi('c1', 'index');
    await moi('c2', 'delete');

    const batch = await buffer.drain();
    expect(batch.sort()).toEqual([
      ['c1', 'index'],
      ['c2', 'delete'],
    ]);
    expect(await buffer.size()).toBe(0);
    // `drain` lan nua khong duoc rut lai lo da ghi xong.
    expect(await buffer.drain()).toEqual([]);
  });

  it('trong luc rut lo, lo cu da sang key dang ghi nen khong co khoang trong', async () => {
    await moi('c1', 'index');

    const draining = buffer.drain();
    // Ngay khi `RENAME` chay xong, khach moi phai vao lo moi chu khong gan them vao lo dang rut.
    const keysMidFlight = await redis!.keys(`${prefix}*`);
    expect(keysMidFlight.some((key) => key.startsWith(processingPrefix))).toBe(true);

    await draining;
    await moi('c2', 'index');
    expect(await buffer.size()).toBe(1);
  });

  it('tra lo chua ghi duoc vao bo dem va bat lai han', async () => {
    await moi('c1', 'index');
    const batch = await buffer.drain();

    await buffer.restore(batch);
    expect(await buffer.size()).toBe(1);
    expect(await buffer.drain()).toEqual([['c1', 'index']]);
  });

  it('quay lai lo bi bo lai khi may chet giua chung', async () => {
    await moi('c1', 'index');
    // Gia lap may chet: rut lo roi tat lien ket noi noi ma khong xoa key dang ghi.
    await redis!.rename(pendingKey, `${processingPrefix}1700000000000`);
    await redis!.hset(`${processingPrefix}1700000000000`, 'c9', 'index');

    const recovered = new RedisPendingBuffer(redis as Redis, cfg as never);
    recovered.start(() => undefined);
    // `recoverOrphans` chay nen trong, cho no quet xong.
    await new Promise((resolve) => setTimeout(resolve, 200));

    expect(await buffer.size()).toBe(2);
    recovered.stop();
  });

  it('bao khi lo het han, khong bao khi lo con moi', async () => {
    const onDue = jest.fn();
    buffer.start(onDue);

    await moi('c1', 'index');
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(onDue).not.toHaveBeenCalled();

    // Dua moc thoi gian ve lau hon `flushIntervalMs` de gia lap qua han.
    await redis!.hset(pendingKey, '__openedAt', String(Date.now() - 5000));
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(onDue).toHaveBeenCalled();

    buffer.stop();
  });
});
