import { registerAs } from '@nestjs/config';

/**
 * Cau hinh Elasticsearch.
 *
 * Mac dinh `enabled = false` de moi truong chua ket noi Elasticsearch van chay duoc:
 * `CustomerSearchService` tu dong lui ve truy van MongoDB. Khi da co cluster, bat bang
 * `ELASTICSEARCH_ENABLED=true` trong `.env`.
 */
export interface ElasticsearchConfig {
  enabled: boolean;
  node: string;
  username?: string;
  password?: string;
  /** Tien to dung de dat ten index va alias, vd `haravan`. */
  indexPrefix: string;
  requestTimeoutMs: number;
  maxRetries: number;
  //  So khach gom duoc bao nhieu thi ghi index ngay.

  batchSize: number;
  /**
   * Thời gian max giữa các lần flush dữ liệu xuống Elasticsearch.
   */
  flushIntervalMs: number;
  /**
   * So khach cho phep giu trong bo dem khi Elasticsearch dang cham.
   *
   * Vuot qua han mo phan chua luu duoc day vao hang doi cong viec (MongoDB) de khong mat du
   * lieu khi tien trinh tu tat. Mac dinh 2000.
   */
  maxPending: number;
  /**
   * Dia chi Redis dung lam bo dem gom lo. Bo trong thi dung bo dem trong RAM cua tien trinh.
   *
   * Mac dinh la Redis tren may. Khong co Redis thi khong gom lo duoc: moi khach se duoc day
   * thang vao hang doi cong viec de ghi rieng, van dung nhung ton them cong viec cho moi khach.
   */
  redisUrl: string;
  /** Tien to ten key, vd `haravan`. tach theo moi truong de khong lan sang nhau. */
  redisKeyPrefix: string;
  /**
   * Chu ky de kiem tra xem lo da het han `flushIntervalMs` chua.
   *
   * Lo du `batchSize` van ghi ngay ngay khi du khach, khong phaii doi tick. Tick chi quyet
   * dinh lo nao `chua du khach va da het han`.
   */
  batchTickMs: number;
  /**
   * So lan mot lo duoc ghi lai trong bo dem truoc khi bo qua.
   *
   * Lo con trong bo dem khi Elasticsearch chat se duoc ghi lai nhieu lan. Neu vuot so lan nay
   * thi giu lai khong ghi tiep va giao cho cong viec doi chieu, tranh ghi lien tuc khi ES that
   * bai. Mac dinh 5.
   */
  maxAttempts: number;
}

export const elasticsearchConfig = registerAs(
  'elasticsearch',
  (): ElasticsearchConfig => ({
    enabled: process.env.ELASTICSEARCH_ENABLED === 'true',
    node: process.env.ELASTICSEARCH_NODE || 'http://localhost:9200',
    username: process.env.ELASTICSEARCH_USERNAME || undefined,
    password: process.env.ELASTICSEARCH_PASSWORD || undefined,
    indexPrefix: process.env.ELASTICSEARCH_INDEX_PREFIX || 'haravan',
    requestTimeoutMs: Number(process.env.ELASTICSEARCH_TIMEOUT_MS || 5000),
    maxRetries: Number(process.env.ELASTICSEARCH_MAX_RETRIES || 2),
    batchSize: Number(process.env.ELASTICSEARCH_BATCH_SIZE || 10),
    flushIntervalMs: Number(
      process.env.ELASTICSEARCH_FLUSH_INTERVAL_MS || 3000,
    ),
    maxPending: Number(process.env.ELASTICSEARCH_MAX_PENDING || 2000),
    redisUrl: process.env.ELASTICSEARCH_REDIS_URL || 'redis://127.0.0.1:6379',
    redisKeyPrefix: process.env.ELASTICSEARCH_REDIS_KEY_PREFIX || 'haravan',
    batchTickMs: Number(process.env.ELASTICSEARCH_BATCH_TICK_MS || 300),
    maxAttempts: Number(process.env.ELASTICSEARCH_MAX_ATTEMPTS || 5),
  }),
);

export const ELASTICSEARCH_CONFIG_KEY = elasticsearchConfig.KEY;
