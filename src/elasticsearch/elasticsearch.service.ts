import {
  Inject,
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { Client } from '@elastic/elasticsearch';
import {
  ELASTICSEARCH_CONFIG_KEY,
  elasticsearchConfig,
  ElasticsearchConfig,
} from './elasticsearch.config';
import {
  customerAliasName,
  customerIndexDefinition,
  customerIndexName,
} from './customer-index.definition';

/**
 * Lop bao phu client Elasticsearch.
 *
 * Nguyen tac: khong bao gio nem loi len tang tren. Khi `ELASTICSEARCH_ENABLED=false` hoac
 * cluster khong phan hoi, moi thao tac deu tra ve gia tri rong nhanh chong de tang tren quyet
 * dinh chay tiep bang MongoDB.
 */
@Injectable()
export class ElasticsearchService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(ElasticsearchService.name);
  private readonly cfg: ElasticsearchConfig;

  private client: Client | null = null;
  private indexReady = false;

  private reachable: boolean | null = null;
  private lastPingAt = 0;
  private readonly pingCooldownMs = 10000;

  /** Chi dung cho muc do log canh bao, tranh canh bao lai 10 giay mot lan. */
  private warnedUnavailable = false;

  constructor(
    @Inject(ELASTICSEARCH_CONFIG_KEY)
    config: ConfigType<typeof elasticsearchConfig>,
  ) {
    this.cfg = config;
  }

  async onModuleInit(): Promise<void> {
    if (!this.cfg.enabled) {
      this.logger.log(
        'Elasticsearch TAT. Tim kiem khach hang se dung MongoDB ' +
          '(ELASTICSEARCH_ENABLED=false).',
      );
      return;
    }

    this.logger.log(`Ket noi Elasticsearch tai ${this.cfg.node}`);
    await this.ensureReady();
  }

  async onModuleDestroy(): Promise<void> {
    await this.client?.close().catch(() => undefined);
    this.client = null;
  }

  /** Co dang bat hay khong; dung de quyet dinh co nen enqueue cong viei dong bo hay khong. */
  isEnabled(): boolean {
    return this.cfg.enabled;
  }

  /** Cluster co phan hoi hay khong. Ket qua duoc cache trong mot khoang de khong ping lien tiep. */
  async isReachable(): Promise<boolean> {
    if (!this.cfg.enabled) return false;

    const now = Date.now();
    if (this.reachable !== null && now - this.lastPingAt < this.pingCooldownMs) {
      return this.reachable;
    }

    try {
      await this.getClient().ping();
      this.reachable = true;
    } catch (error) {
      this.reachable = false;
      this.warnUnavailable('khong ket noi duoc', error);
    }

    this.lastPingAt = now;
    return this.reachable;
  }

  /** Dam bao index va alias ton tai. An toan khi goi nhieu lan. */
  async ensureReady(): Promise<boolean> {
    if (this.indexReady) return true;
    if (!(await this.isReachable())) return false;

    const client = this.getClient();
    const index = customerIndexName(this.cfg.indexPrefix);
    const alias = customerAliasName(this.cfg.indexPrefix);

    try {
      const exists = await client.indices.exists({ index });
      if (!exists) {
        await client.indices.create({ index, ...customerIndexDefinition() });
        this.logger.log(`Da tao index ${index}`);
      }

      await this.pointAliasToIndex(client, alias, index);

      this.indexReady = true;
      this.reachable = true;
      this.warnedUnavailable = false;
      return true;
    } catch (error) {
      this.warnUnavailable('khong tao duoc index', error);
      return false;
    }
  }

  /**
   * Tro alias vao index moi nhat.
   *
   * Do la cach doi mapping khi `CUSTOMER_INDEX_VERSION` tang. Code chi doc qua alias nen
   * truy van khong bao gio bi ngat, va index cu van con nguyen de doi chieu neu can.
   */
  private async pointAliasToIndex(
    client: Client,
    alias: string,
    index: string,
  ): Promise<void> {
    let current: string[] = [];
    try {
      const info = await client.indices.getAlias({ name: alias });
      current = Object.keys(info ?? {});
    } catch {
      // Chua co alias nao — se tao moi o duoi.
    }

    const stale = current.filter((name) => name !== index);
    if (!stale.length && current.includes(index)) return;

    await client.indices.updateAliases({
      actions: [
        ...stale.map((name) => ({ remove: { index: name, alias } })),
        { add: { index, alias } },
      ],
    });

    this.logger.log(
      `Alias ${alias} -> ${index}` +
        (stale.length ? ` (thay the ${stale.join(', ')})` : ''),
    );
  }

  /**
   * Ghi mot loat document vao index khach hang.
   *
   * Dung `version_type: external_gte` voi `version` lay tu `syncedAt`, nen hai worker cung ghi
   * mot khach se khong ghi de ban moi bang ban cu hon.
   */
  async bulkIndexCustomers(
    docs: Array<Record<string, unknown>>,
    ids: string[],
  ): Promise<boolean> {
    if (!docs.length) return true;
    if (!(await this.ensureReady())) return false;

    const client = this.getClient();
    const index = customerAliasName(this.cfg.indexPrefix);

    const operations = docs.flatMap((doc, i) => {
      const version = Number(doc['syncedAt'] ?? Date.now()) || Date.now();
      return [
        {
          index: {
            _index: index,
            _id: ids[i],
            version,
            version_type: 'external_gte' as const,
          },
        },
        doc,
      ];
    });

    try {
      const result = await client.bulk({ operations, refresh: false });
      if (result.errors) {
        const rejected = result.items.filter((item) => item.index?.error);

        // `version_conflict_engine_exception` xuat ra khi ban ghi moi hon ban vua ghi: `external_gte`
        // tu choi dung y vay. Do la trang thai dung cua index chu khong phai loi, nen khong tinh
        // vao `failed` — neu tinh, ca lo se bi thu lai vo ich va lam nhieu ghi hon vao index.
        const outdated = rejected.filter(
          (item) =>
            (item.index?.error as { type?: string } | undefined)?.type ===
            'version_conflict_engine_exception',
        );
        const failed = rejected.filter(
          (item) =>
            (item.index?.error as { type?: string } | undefined)?.type !==
            'version_conflict_engine_exception',
        );

        if (outdated.length) {
          this.logger.log(
            `Bo qua ${outdated.length} document da co ban moi hon trong index ` +
              `(${outdated.length}/${docs.length} cua lo nay)`,
          );
        }

        if (!failed.length) return true;

        // Phai in ra ly do that: mapping sai (vi du kieu so vuot gioi han) se lam moi
        // document bi tu choi ma khong co duoi tin nao.
        const first = failed[0]?.index?.error as
          | { type?: string; reason?: string }
          | undefined;
        this.logger.error(
          `Ghi Elasticsearch that bai ${failed.length}/${docs.length} document` +
            (first ? `: [${first.type}] ${first.reason}` : ''),
        );
        return false;
      }
      return true;
    } catch (error) {
      this.markUnavailable(error);
      return false;
    }
  }

  /** Xoa mot khach khoi index. Tra ve `false` khi khong truy van duoc. */
  async deleteCustomer(id: string): Promise<boolean> {
    if (!(await this.ensureReady())) return false;

    try {
      await this.getClient().delete({
        index: customerAliasName(this.cfg.indexPrefix),
        id,
        refresh: false,
      });
      return true;
    } catch (error) {
      const status = (error as { meta?: { statusCode?: number } })?.meta
        ?.statusCode;
      // 404 nghia la document da khong con; truy van khong sai.
      if (status === 404) return true;
      this.markUnavailable(error);
      return false;
    }
  }

  /**
   * Xoa nhieu khach trong mot lenh `bulk`.
   *
   * Cung co do hienh `deleteCustomer`, nhung goi theo lo nen mot lan xoa duoc nhieu khach.
   * Document da khong con trong index khong phai la loi nen bo qua, tranh viec loi retry ca
   * lo vi mot ban ghi da bien mat truoc do.
   */
  async bulkDeleteCustomers(ids: string[]): Promise<boolean> {
    if (!ids.length) return true;
    if (!(await this.ensureReady())) return false;

    const index = customerAliasName(this.cfg.indexPrefix);
    const operations = ids.map((id) => ({ delete: { _index: index, _id: id } }));

    try {
      const result = await this.getClient().bulk({ operations, refresh: false } as never);
      if (!result.errors) return true;

      // `delete` khong tim thay document la trang thai da dung, khong phai loi can xu ly.
      const failed = result.items.filter(
        (item) => item.delete && item.delete.status !== 404,
      );
      if (!failed.length) return true;

      const first = failed[0]?.delete?.error as
        | { type?: string; reason?: string }
        | undefined;
      this.logger.error(
        `Xoa Elasticsearch that bai ${failed.length}/${ids.length} document` +
          (first ? `: [${first.type}] ${first.reason}` : ''),
      );
      return false;
    } catch (error) {
      this.markUnavailable(error);
      return false;
    }
  }

  /** Chay truy van tren index khach hang; tra ve `null` khi khong truy van duoc. */
  async searchCustomerIndex<T = Record<string, unknown>>(
    params: Record<string, unknown>,
  ): Promise<{ total: number; hits: T[] } | null> {
    if (!(await this.ensureReady())) return null;

    try {
      const result = await this.getClient().search<T>({
        index: customerAliasName(this.cfg.indexPrefix),
        ...params,
      } as never);
      const total =
        typeof result.hits.total === 'number'
          ? result.hits.total
          : (result.hits.total?.value ?? 0);
      const hits = result.hits.hits.map((hit) => hit._source as T);
      return { total, hits };
    } catch (error) {
      this.markUnavailable(error);
      return null;
    }
  }

  /** Dem so khach dang trong index; dung de doi chieu do lech sau khi backfill. */
  async countCustomerIndex(): Promise<number | null> {
    if (!(await this.ensureReady())) return null;

    try {
      const result = await this.getClient().count({
        index: customerAliasName(this.cfg.indexPrefix),
      });
      return result.count;
    } catch (error) {
      this.markUnavailable(error);
      return null;
    }
  }

  /* ------------------------------- noi bo */

  private getClient(): Client {
    if (!this.client) {
      this.client = new Client({
        node: this.cfg.node,
        auth:
          this.cfg.username && this.cfg.password
            ? { username: this.cfg.username, password: this.cfg.password }
            : undefined,
        requestTimeout: this.cfg.requestTimeoutMs,
        maxRetries: this.cfg.maxRetries,
      });
    }
    return this.client;
  }

  private markUnavailable(error: unknown): void {
    this.reachable = false;
    this.indexReady = false;
    this.warnUnavailable('loi khi truy van Elasticsearch', error);
  }

  private warnUnavailable(reason: string, error?: unknown): void {
    if (this.warnedUnavailable) return;
    this.warnedUnavailable = true;
    // Elasticsearch nem loi rat dai, chi lay `message` se cat mat nguyen nhan that.
    const detail = this.describeError(error);
    this.logger.warn(
      `${reason}: ${detail}. ` +
        'Chuyen sang dung MongoDB cho toi khi ket noi lai.',
    );
  }

  /** Lay cau loi cu the tu response cua Elasticsearch thay vi chi lay ten loi. */
  private describeError(error?: unknown): string {
    if (!error) return 'khong ro nguyen nhan';

    const body = (error as { meta?: { body?: unknown } })?.meta?.body as
      | { error?: { root_cause?: Array<{ reason?: string }>; reason?: string } }
      | undefined;
    const detail = body?.error?.root_cause?.[0]?.reason ?? body?.error?.reason;
    if (detail) return detail;

    return (error as Error)?.message ?? 'khong ro nguyen nhan';
  }
}
