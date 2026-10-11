import Redis from 'ioredis';
import type { ClientContext, Result } from 'ioredis';
import { Logger } from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { elasticsearchConfig } from './elasticsearch.config';
import { PendingBuffer, PendingOp } from './batch-buffer';

/**
 * Field giu moc thoi gian khach dau tien cua lo, nam trong chinh hash cua lo.
 *
 * De chung mot hash voi danh sach khach de `RENAME` rut ca lo di duoc trong mot lenh nguyen tu.
 * Neu tach ra mot key rieng, se xay ra tinh huong: rut lo xong, khach moi den (dat moc thoi gian
 * moi), roi `DEL` moc thoi gian cu, lo moi khong con han va khong bao gio duoc ghi theo han.
 *
 * Ten field bat dau bang `__` nen khong bao gio trung id khach (id la chuoi hex 24 ky tu).
 */
const OPENED_AT_FIELD = '__openedAt';

/**
 * Chen mot khach vao lo va tra ve so khach dang cho.
 *
 * Gop trong mot script de chi ton mot lan di toi Redis va de `HSETNX` (chi dat moc thoi gian khi
 * lo moi) chay ngay trong cung lenh, khong co khoang giua ma lo rong nhung khach da tinh vao so dem.
 */
const LUA_ENQUEUE = [
  "redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])",
  `redis.call('HSETNX', KEYS[1], '${OPENED_AT_FIELD}', ARGV[3])`,
  "return redis.call('HLEN', KEYS[1]) - 1",
].join('\n');

/**
 * Rut nguyen lo hien tai sang key dang ghi.
 *
 * `RENAME` la nguyen tu nen khong bao gio co khoang thoi gian ma bo dem rong. Lo duoc giu trong key
 * `processing` va chi xoa sau khi ghi xong nen may chet giua chung thi lo van con, lan chay sau se
 * quay lai.
 */
const LUA_DRAIN = [
  "if redis.call('EXISTS', KEYS[1]) == 0 then",
  '  return 0',
  'end',
  "redis.call('RENAME', KEYS[1], ARGV[1])",
  'return 1',
].join('\n');

/**
 * Doc het mot key roi xoa trong mot lenh.
 *
 * Doc `HGETALL` roi `DEL` bang hai lenh se de lao khoang thoi gian ma lenh thu hai cua tien trinh
 * nao do chen vao xoa nham. Mot script thi khong.
 */
const LUA_TAKE = [
  "local values = redis.call('HGETALL', KEYS[1])",
  "redis.call('DEL', KEYS[1])",
  'return values',
].join('\n');

/**
 * Tra mot lo da rut lai ve bo dem.
 *
 * `HSETNX` dat lai moc thoi gian khi lo dang rong: han bat lai tu luc tra lai chu khong phai tu
 * luc lo cu, neu khong lo tra lai se duoc ghi ngay lap tuc trong khi Elasticsearch con chay.
 */
const LUA_RESTORE = [
  `redis.call('HSETNX', KEYS[1], '${OPENED_AT_FIELD}', ARGV[1])`,
  'for i = 2, #ARGV, 2 do',
  "  redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1])",
  'end',
  "return redis.call('HLEN', KEYS[1]) - 1",
].join('\n');

// Cac lenh tu dinh nghia o tren. Khai bao them de TypeScript biet ten lenh, `defineCommand` tu
// chay `EVALSHA` va tu quay lai `EVAL` khi Redis vua khoi dong (chua co script trong cache).
declare module 'ioredis' {
  interface RedisCommander<Context extends ClientContext = { type: 'default' }> {
    esEnqueue(key: string, id: string, op: string, now: string): Result<number, Context>;
    esDrain(key: string, target: string): Result<number, Context>;
    esTake(key: string): Result<string[], Context>;
    esRestore(key: string, ...args: string[]): Result<number, Context>;
  }
}

/**
 * Bo dem gom lo trong Redis, dung chung cho moi tien trinh.
 *
 * Han vi giong het bo dem trong RAM truoc day: `HSET` ghi de nen cung mot khach nhieu lan chi con
 * mot muc, va thao tac sau cung ghi de thao tac truoc nen sua roi xoa trong cung mot lo ra "xoá".
 *
 * Khac mot noi so voi bo dem trong RAM: ket noi qua mang nen moi ham deu `await`, va loi nem ra de
 * ben tren chuyen viec ghi sang hang doi cong viec thay vi treo duong ghi khach.
 */
export class RedisPendingBuffer implements PendingBuffer {
  private readonly logger = new Logger(RedisPendingBuffer.name);
  private readonly pendingKey: string;
  private readonly processingPrefix: string;

  private tickTimer: NodeJS.Timeout | null = null;
  private closing = false;
  private onDue: (() => void) | null = null;
  private started = false;

  constructor(
    private readonly redis: Redis,
    private readonly cfg: ConfigType<typeof elasticsearchConfig>,
  ) {
    const prefix = this.cfg.redisKeyPrefix || 'haravan';
    this.pendingKey = `${prefix}:es:pending`;
    this.processingPrefix = `${prefix}:es:processing:`;

    this.redis.defineCommand('esEnqueue', { numberOfKeys: 1, lua: LUA_ENQUEUE });
    this.redis.defineCommand('esDrain', { numberOfKeys: 1, lua: LUA_DRAIN });
    this.redis.defineCommand('esTake', { numberOfKeys: 1, lua: LUA_TAKE });
    this.redis.defineCommand('esRestore', { numberOfKeys: 1, lua: LUA_RESTORE });

    this.redis.on('error', (error: Error) =>
      this.logger.warn(`Redis ba dem loi: ${error.message}`),
    );
  }

  /** Ghi mot khach vao lo; loi se nem ra de ben tren dua viec ghi sang hang doi cong viec. */
  async add(id: string, op: PendingOp): Promise<number> {
    return Number(
      await this.redis.esEnqueue(this.pendingKey, id, op, String(Date.now())),
    );
  }

  /**
   * Rut nguyen lo hien tai.
   *
   * Buoc 1 `RENAME` sang `processing:<ts>` (nguyen tu, khong co khoang trong), buoc 2 `HGETALL` +
   * `DEL` trong mot lenh.
   *
   * Khong rut duoc thi tra ve mang rong thay vi nem loi: loi cua Redis de ben tren xu ly.
   */
  async drain(): Promise<Array<[string, PendingOp]>> {
    const target = `${this.processingPrefix}${Date.now()}`;

    const moved = Number(await this.redis.esDrain(this.pendingKey, target));
    if (!moved) return [];

    return toBatch((await this.redis.esTake(target)) as string[]);
  }

  async restore(batch: Array<[string, PendingOp]>): Promise<void> {
    if (!batch.length) return;
    const args: string[] = [String(Date.now())];
    for (const [id, op] of batch) args.push(id, op);
    await this.redis.esRestore(this.pendingKey, ...args);
  }

  async size(): Promise<number> {
    return Math.max(0, (await this.redis.hlen(this.pendingKey)) - 1);
  }

  /**
   * Bat lich quet de chay lo theo han.
   *
   * Khong dung `setTimeout` nhu bo dem trong RAM: nhac quet co hai uu diem, viec khong mat khi tien
   * trinh chet va nhieu tien trinh deu thay lo da het han nao du may nao cung chay.
   *
   * Lo du `batchSize` khong phai doi den tick: `add` bao ve ben duoc roi ben tren flush ngay. Tick
   * chi lo phai cho `flushIntervalMs`.
   */
  start(onDue: () => void): void {
    this.onDue = onDue;
    if (this.started || this.closing) return;
    this.started = true;

    void this.recoverOrphans();

    this.tickTimer = setInterval(() => void this.tick(), this.cfg.batchTickMs);
    // `unref` de lenh nay khong giu tien trinh song khi he thong dang tat.
    this.tickTimer.unref?.();
  }

  stop(): void {
    this.onDue = null;
    if (this.tickTimer) clearInterval(this.tickTimer);
    this.tickTimer = null;
  }

  close(): void {
    this.closing = true;
    this.stop();
    this.redis.disconnect();
  }

  /* ------------------------------- noi bo */

  /**
   * Dua cac lo bi bo lai khi may chet giua chung chay vao lai bo dem.
   *
   * Mot lo con nam trong `processing:<ts>` la lo chua ghi xong ma tien trinh da chet. Chinh ly do bo
   * dem nay ton tai thay vi bo dem trong RAM.
   */
  private async recoverOrphans(): Promise<void> {
    try {
      let cursor = '0';
      do {
        const [next, keys] = await this.redis.scan(
          cursor,
          'MATCH',
          `${this.processingPrefix}*`,
          'COUNT',
          100,
        );
        cursor = next;

        for (const key of keys) {
          const batch = toBatch((await this.redis.esTake(key)) as string[]);
          if (!batch.length) continue;
          await this.restore(batch);
          this.logger.warn(
            `Tim thay ${batch.length} khach chua ghi xong tu lan chay truoc, dua vao lai bo dem`,
          );
        }
      } while (cursor !== '0');
    } catch (error) {
      this.logger.warn(
        `Khong quet lai duoc lo cu bi bo lai: ${(error as Error).message}`,
      );
    }
  }

  /**
   * Kiem tra lo da het han chua; het thi bao cho ben tren flush.
   *
   * Hai dieu kien giong het bo dem trong RAM: du `batchSize`, hoac qua `flushIntervalMs` tinh tu
   * khach dau tien cua lo. Moc thoi gian nam trong chinh hash nen moi tien trinh deu thay cung
   * mot moc.
   */
  private async tick(): Promise<void> {
    if (this.closing || !this.onDue) return;

    try {
      const [openedAt] = (await this.redis.hmget(
        this.pendingKey,
        OPENED_AT_FIELD,
      )) as [string | null];
      if (!openedAt) return;

      const size = await this.size();
      if (
        size >= this.cfg.batchSize ||
        Date.now() - Number(openedAt) >= this.cfg.flushIntervalMs
      ) {
        this.onDue();
      }
    } catch {
      // Redis hong: ben tren xu ly, im lang de khong ghi log lien tuc.
    }
  }
}

/** Bo `HGETALL` ve lai dang `[id, 'index']`, bo qua field moc thoi gian. */
function toBatch(values: string[]): Array<[string, PendingOp]> {
  const batch: Array<[string, PendingOp]> = [];
  for (let i = 0; i < values.length; i += 2) {
    if (values[i] === OPENED_AT_FIELD) continue;
    batch.push([values[i], values[i + 1] as PendingOp]);
  }
  return batch;
}

/**
 * Ket noi Redis va tra ve bo dem.
 *
 * `enableOfflineQueue: false` va `maxRetriesPerRequest: 1` la chu dich quan trong: khi Redis chet,
 * lenh phai that bai ngay thay vi doi mot giay moi lai, vi `add` duoc goi ngay trong duong ghi khach,
 * cho doi lai se lam chan ghi MongoDB.
 */
export function createPendingBuffer(
  cfg: ConfigType<typeof elasticsearchConfig>,
  logger: Logger,
): PendingBuffer {
  const redis = new Redis(cfg.redisUrl, {
    connectTimeout: 2000,
    enableOfflineQueue: false,
    maxRetriesPerRequest: 1,
    // Gioi han do phai cho: Redis chet thi dung thu lai vo han va giu tien trinh song.
    retryStrategy: (times: number) => Math.min(times * 200, 5000),
  });

  logger.log(`Gom lo khach bang Redis tai ${cfg.redisUrl}`);
  return new RedisPendingBuffer(redis, cfg);
}
