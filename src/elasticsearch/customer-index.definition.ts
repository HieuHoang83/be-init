import { IndicesCreateRequest } from '@elastic/elasticsearch/lib/api/types';

/** Phien ban mapping. Tang so nay moi khi doi mapping khong tuong thich. */
export const CUSTOMER_INDEX_VERSION = 3;

/** Ten index ghi du lieu, vd `haravan-customers-v1`. */
export function customerIndexName(prefix: string): string {
  return `${prefix}-customers-v${CUSTOMER_INDEX_VERSION}`;
}

/**
 * Ten alias ma code luon truy van, vd `haravan-customers`.
 *
 * Reindex khong dung doc truc tiep `customerIndexName` ma doi alias sang index moi, nho do
 * khong co thoi gian ma truy van bi dung.
 */
export function customerAliasName(prefix: string): string {
  return `${prefix}-customers`;
}

/**
 * Mapping va settings cho index khach hang.
 *
 * `phoneSuffix3` la truong chinh dung de tim 3 chu so cuoi, khai bao `keyword` de truy van
 * bang `term` — chinh xac tuyet doi, khong bao gio khop nham mot cum o giua so dien thoai.
 *
 * `phonePrefix` chi dung khi nguoi dung go so dien thoai tu dau (vd `0961`); nó dung
 * `edge_ngram` nen chi ho tro khop o dau chuoi, dung `search_analyzer` de cau truy van
 * khong bi cat nho.
 */
export function customerIndexDefinition(): Omit<IndicesCreateRequest, 'index'> {
  return {
    settings: {
      number_of_shards: 1,
      number_of_replicas: 0,
      analysis: {
        analyzer: {
          phone_edge: {
            type: 'custom',
            tokenizer: 'standard',
            filter: ['lowercase', 'phone_edge_ngram'],
          },
          phone_search: {
            type: 'custom',
            tokenizer: 'standard',
            filter: ['lowercase'],
          },
        },
        filter: {
          phone_edge_ngram: {
            type: 'edge_ngram',
            min_gram: 3,
            max_gram: 5,
          },
        },
      },
    },
    mappings: {
      properties: {
        id: { type: 'keyword' },
        /**
         * `long` chu khong phai `integer`: ma shop cua Haravan la so lon (vi du `200001220496`),
         * vuot qua gioi han 32 bit cua `integer` nen se lam moi document bi tu choi.
         */
        orgId: { type: 'long' },
        haravanCustomerId: { type: 'long' },
        fullName: { type: 'text' },
        firstName: { type: 'text' },
        lastName: { type: 'text' },
        email: {
          type: 'keyword',
          fields: { text: { type: 'text' } },
        },
        phone: { type: 'keyword' },
        /** Ba chu so cuoi cua so dien thoai, vd `633`. */
        phoneSuffix3: { type: 'keyword' },
        /** Ho tro nguoi dung go so dien thoai tu dau, vd `0961`. */
        phonePrefix: {
          type: 'text',
          analyzer: 'phone_edge',
          search_analyzer: 'phone_search',
        },
        state: { type: 'keyword' },
        verifiedEmail: { type: 'boolean' },
        haravanOrdersCount: { type: 'integer' },
        haravanTotalSpent: { type: 'double' },
        beOrderCount: { type: 'integer' },
        beTotalSpent: { type: 'double' },
        lastOrderId: { type: 'long' },
        lastOrderName: { type: 'keyword' },
        orderIds: { type: 'long' },
        firstSeenAt: { type: 'date' },
        lastSeenAt: { type: 'date' },
        createdAt: { type: 'date' },
        updatedAt: { type: 'date' },
        /** Monotonic counter, gan o Mongo de tranh worker cu ghi de ban moi bang ban cu. */
        syncedAt: { type: 'date' },
      },
    },
  };
}
