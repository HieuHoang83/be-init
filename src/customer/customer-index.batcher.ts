import {
  Inject,
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { ElasticsearchService } from '../elasticsearch/elasticsearch.service';
import {
  ELASTICSEARCH_CONFIG_KEY,
  elasticsearchConfig,
} from '../elasticsearch/elasticsearch.config';
import { PendingBuffer, PendingOp } from '../elasticsearch/batch-buffer';
import { createPendingBuffer } from '../elasticsearch/redis-batch-buffer';
import { JobQueue, JOB_NAMES } from '../queue/queue.service';
import { CustomerIndexService } from './customer-index.service';

/**
 * Cho phep doi toi da bao nhieu giay khi dung tien trinh.
 *
 * Ghi Elasticsearch co the treo bang `ELASTICSEARCH_TIMEOUT_MS` x `MAX_RETRIES`, viec tat tien
 * trinh khong nen bi treo vi vay.
 */
const SHUTDOWN_FLUSH_TIMEOUT_MS = 5000;

/**
 * Gom cong viec nap index thanh lo thay vi ghi ngay tung khach.
 *
 * Truoc day moi khach viet lai se day mot job `customer.es_sync` vao MongoDB, worker xu ly xong roi
 * goi Elasticsearch. Mot lan Haravan/webhook ghi 20 khach thi cung la 20 job + 20 request `bulk` va
 * 20 lan doc MongoDB, phan bo rat nho so voi cong viec thuc te.
 *
 * Lop nay giu khach trong bo dem **Redis** roi ghi theo **hai dieu kien, cai nao den truoc cung duoc**:
 *
 * 1. **Du `batchSize` khach** (mac dinh 10) trong lo hien tai, ghi ngay;
 * 2. **Het `flushIntervalMs`** (mac dinh 3000ms) tinh tu khach dau tien cua lo.
 *
 * Vong lap: gom -> len lo -> ghi mot `bulk` -> xoa lo -> reset. Khach bi ghi nhieu lan trong cung
 * mot lo chi con mot lan ghi, va thao tac sau cung thang thay loi truoc (sua 3 lan roi xoa trong 3 giay
 * thi chi xoa mot lan).
 *
 * Bo dem nam trong Redis chu khong phai RAM cua tien trinh, nen moi tien trinh deu thay cung mot lo,
 * lo chua ghi xong con nam lai duoc cho lan chay sau thay vi mat khi may chet. Khi khong noi duoc
 * Redis, khach duoc day thang vao hang doi cong viec: ghi khach khong bao gio bi chan boi ha tang phu.
 *
 * Lo chua ghi duoc gan `ES_INDEX_MAX_PENDING` cung duoc day vao hang doi cong viec de khong mat du
 * lieu, va `POST /api/v1/customers/reindex` nap lai toan bo khi can.
 */
@Injectable()
export class CustomerIndexBatcher implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(CustomerIndexBatcher.name);
  private readonly cfg: ConfigType<typeof elasticsearchConfig>;

  /** Bo dem gom lo trong Redis, dung chung cho moi tien trinh. */
  private readonly buffer: PendingBuffer;

  /** Xep cac lan ghi theo thu tu de khong hai `bulk` chay chung va ghi lo vao nhau. */
  private chain: Promise<void> = Promise.resolve();

  private stopping = false;

  /* Thong ke chi de doc log, khong dung cho nghiep vu va khong phai noi luu khach. */
  private pendingHint = 0;
  private flushedBatches = 0;
  private flushedDocs = 0;
  private spilledDocs = 0;
  private failures = 0;

  constructor(
    @Inject(ELASTICSEARCH_CONFIG_KEY) config: ConfigType<typeof elasticsearchConfig>,
    private readonly es: ElasticsearchService,
    private readonly indexService: CustomerIndexService,
    private readonly jobQueue: JobQueue,
  ) {
    this.cfg = config;
    this.buffer = this.createBuffer();
  }

  /**
   * Tao bo dem gom lo.
 *
 * Tach rieng de test lay bo dem gia thay vi noi that: test khong nen mo ket noi Redis.
   */
  protected createBuffer(): PendingBuffer {
    return createPendingBuffer(this.cfg, this.logger);
  }

  onModuleInit(): void {
    if (!this.es.isEnabled()) return;

    this.buffer.start(() => void this.flush());
    this.logger.log(
      `Gom nap index khach: ghi khi du ${this.cfg.batchSize} khach ` +
        `hoac het ${this.cfg.flushIntervalMs}ms`,
    );
  }

  /** Nap lai mot khach; dung cho duong ghi chuan sau khi MongoDB da ghi xong. */
  enqueue(customerId: string): void {
    this.push(customerId, 'index');
  }

  /** Xoa mot khach khoi index; dung sau khi ban ghi da bi xoa o MongoDB. */
  enqueueDelete(customerId: string): void {
    this.push(customerId, 'delete');
  }

  /**
   * Ghi ngay phan chua dung, khong cho doi.
   *
   * Dung khi tien trinh sap dung va khi can index co ban ngay (sau khi nap lai toan bo).
   */
  async flush(): Promise<void> {
    const batch = await this.buffer.drain();
    if (!batch.length) return;

    this.pendingHint = Math.max(0, this.pendingHint - batch.length);
    this.chain = this.chain
      .then(() => this.run(batch, 1))
      .catch(() => undefined);
    return this.chain;
  }

  /**
   * Day phan chua sang hang doi cong viec.
   *
   * Dung khi bo dem tran `maxPending`: giu cong viec trong bo dem chi lam cham them, trong khi hang
   * doi MongoDB da co san co che gia han, backoff va phan chia giua nhieu tien trinh.
   */
  private async spill(): Promise<void> {
    const batch = await this.buffer.drain();
    if (!batch.length) return;

    this.pendingHint = Math.max(0, this.pendingHint - batch.length);
    this.spilledDocs += batch.length;
    this.pushToQueue(batch);
    this.logger.warn(
      `Bo dem nap index tran ${this.cfg.maxPending} khach, chuyen ${batch.length} sang hang doi`,
    );
  }

  /** Trang thai hien tai, dung de ghi log va canh bao. */
  stats(): {
    pending: number;
    batches: number;
    docs: number;
    spilled: number;
    failures: number;
  } {
    return {
      pending: this.pendingHint,
      batches: this.flushedBatches,
      docs: this.flushedDocs,
      spilled: this.spilledDocs,
      failures: this.failures,
    };
  }

  /* ------------------------------- noi bo */

  /** Nap vao bo dem va quyet dinh co ghi ngay hay cho het han. */
  private push(customerId: string, op: PendingOp): void {
    if (!this.es.isEnabled() || this.stopping) return;

    void this.buffer
      .add(customerId, op)
      .then((size) => {
        this.pendingHint = size;

        if (size >= this.cfg.maxPending) {
          void this.spill();
          return;
        }

        // Du ngan: ghi ngay, khong doi het han.
        if (size >= this.cfg.batchSize) void this.flush();
      })
      .catch((error: Error) => this.toJobQueue(error, customerId, op));
  }

  /**
   * Redis khong dung: day thang khach nay sang hang doi cong viec.
   *
   * Khach dang ghi Mongo van ghi binh thuong, chi viec nap index bi chuyen duong. Cong viec trong
   * Mongo thi ben vung, co backoff va chay lai duoc tren may khac, nen an toan hon giu trong RAM.
   */
  private toJobQueue(error: Error, customerId: string, op: PendingOp): void {
    this.logger.warn(
      `Khong them vao bo dem Redis duoc (${error.message}), ` +
        `chuyen ${customerId} sang hang doi cong viec`,
    );
    this.pushToQueue([[customerId, op]]);
  }

  /** Ghi mot lo: doc MongoDB mot lan roi goi Elasticsearch mot lan. */
  private async run(batch: Array<[string, PendingOp]>, attempt: number): Promise<void> {
    const indexIds: string[] = [];
    const deleteIds: string[] = [];
    for (const [id, op] of batch) (op === 'index' ? indexIds : deleteIds).push(id);

    const failed: string[] = [];
    let deleted = 0;

    try {
      if (indexIds.length) {
        const result = await this.indexService.syncCustomers(indexIds);
        deleted += result.deleted;
        failed.push(...result.failed);
      }

      if (deleteIds.length && !(await this.es.bulkDeleteCustomers(deleteIds))) {
        failed.push(...deleteIds);
      } else {
        deleted += deleteIds.length;
      }
    } catch (error) {
      // Lo ghi duoc bo dem lai bang loi (MongoDB mat ket noi, lenh doc bi timeout...) thi chua
      // khach nao duoc ghi. Khong duoc bo qua: loi se chay len `chain` o `flush()` va bi nuot mat,
      // khong log, khong thu lai, khach lao trong RAM bay bien khong con duong nao nap lai nua.
      this.logger.error(
        `Lo nap index gap loi (${batch.length} khach): ` +
          `${(error as Error)?.message ?? error}`,
      );
      failed.push(...indexIds, ...deleteIds);
    }

    this.flushedBatches += 1;
    this.flushedDocs += batch.length;
    this.failures += failed.length;

    if (failed.length) await this.retry(batch, attempt, failed);

    // Khong log tung lo: khi khach ve lien tuc thi moi 3 giay la mot dong, den ngap nhanh chua can
    // xem. Thinh thoang moi tom tat de canh bao khi ES cham.
    if (this.flushedBatches % 20 === 0 || failed.length) {
      this.logger.log(
        `Nap index: ${batch.length} khach trong lo (ghi ${indexIds.length}, xoa ${deleted}) ` +
          `\u2014 tong ${this.flushedDocs} khach / ${this.flushedBatches} lo, ` +
          `that bai ${this.failures}, tran ${this.spilledDocs}, ` +
          `cho ${this.pendingHint}`,
      );
    }
  }

  /**
   * Xu ly lo ghi khong duoc.
   *
   * Elasticsearch chap tam thoi thi ghi lai vao bo dem cho chay lai o lo sau, khong ton them dong
   * nao trong DB. Con lai duoc day vao hang doi cong viec de worker thu lai theo backoff va chay du
   * tren may khac, va khong mat khi may nay dung.
   */
  private async retry(
    batch: Array<[string, PendingOp]>,
    attempt: number,
    failed: string[],
  ): Promise<void> {
    const failedSet = new Set(failed);
    const failedBatch = batch.filter(([id]) => failedSet.has(id));

    if (attempt < this.cfg.maxAttempts) {
      await this.buffer.restore(failedBatch);
      this.logger.warn(
        `${failed.length} khach chua ghi duoc vao index, ghi lai vao bo dem de thu lai ` +
          `(lan ${attempt + 1}/${this.cfg.maxAttempts})`,
      );
      return;
    }

    this.logger.warn(
      `${failed.length} khach chua ghi duoc vao index, chuyen sang hang doi de thu lai`,
    );
    this.pushToQueue(failedBatch);
  }

  /**
   * Day mot lo len hang doi cong viec de worker xu lai theo backoff.
   *
   * `maxAttempts` dat cao hon mac dinh cua hang doi: Elasticsearch chap vai chuc giay la chua phai
   * bo ca lo khach va chay lai `POST /api/v1/customers/reindex`.
   */
  private pushToQueue(batch: Array<[string, PendingOp]>): void {
    const customerIds: string[] = [];
    const deleteIds: string[] = [];

    for (const [id, op] of batch) (op === 'index' ? customerIds : deleteIds).push(id);

    if (!customerIds.length && !deleteIds.length) return;

    void this.jobQueue
      .enqueue(
        JOB_NAMES.CUSTOMER_ES_SYNC,
        { customerIds, deleteIds },
        { maxAttempts: 10 },
      )
      .catch((error: Error) =>
        this.logger.error(
          `Khong day duoc cong viec nap index vao hang doi: ${error.message}`,
        ),
      );
  }

  /**
   * Ghi nhung con trong bo dem truoc khi dung.
   *
   * Uu tien ghi luon phan dang cho doi thoit han 3 giay, nen phan con lai trong bo dem (sinh ra sau
   * khi `flush()` bat dau) moi dua sang hang doi cong viec. Chi doi toi da `SHUTDOWN_FLUSH_TIMEOUT_MS`
   * de mot lan `bulk` qua cham khong lam treo viec tat tien trinh.
   */
  async onModuleDestroy(): Promise<void> {
    this.stopping = true;
    this.buffer.stop();

    let timer: NodeJS.Timeout | undefined;
    await Promise.race([
      this.flush(),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, SHUTDOWN_FLUSH_TIMEOUT_MS);
        timer.unref?.();
      }),
    ]);
    if (timer) clearTimeout(timer);

    // Phan sinh ra sau khi `flush()` bat dau thi giu lai trong Redis cho lan chay sau.
    this.buffer.close();
  }
}
