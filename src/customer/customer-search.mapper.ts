import { Customer } from '../order/entities/customer.entity';
import { normalizePhone } from '../order/mappers/order.mapper';

/** So chu so cuoi duoc dung lam khoa tim kiem chinh. */
export const PHONE_SUFFIX_LENGTH = 3;

/**
 * Lay ba chu so cuoi cua so dien thoai da chuan hoa.
 *
 * Chu hoa lai bang `normalizePhone` de khop dung voi gia tri da luu trong MongoDB; neu bo qua
 * buoc nay, so `84961277633` se ra hau to `633` con so `0961277633` cung ra `633` nhung truong
 * hop cac phu thuoc se lech nhau.
 */
export function phoneSuffix3(phone?: string | null): string | undefined {
  const normalized = normalizePhone(phone);
  if (!normalized || normalized.length < PHONE_SUFFIX_LENGTH) return undefined;
  return normalized.slice(-PHONE_SUFFIX_LENGTH);
}

/** Chuyen document Mongo thanh document Elasticsearch. */
export function toCustomerIndexDoc(
  customer: Customer & {
    _id?: unknown;
    /** Mongoose tu them hai truong nay qua `timestamps: true`. */
    createdAt?: Date;
    updatedAt?: Date;
  },
): Record<string, unknown> {
  const phone = normalizePhone(customer.phone);

  return {
    id: String(customer._id ?? ''),
    orgId: customer.orgId,
    haravanCustomerId: customer.haravanCustomerId,
    fullName: customer.fullName,
    firstName: customer.firstName,
    lastName: customer.lastName,
    email: customer.email,
    phone,
    phoneSuffix3: phoneSuffix3(phone),
    /**
     * Ghi nguyen so dien thoai vao truong nay; analyzer `phone_edge` (edge_ngram) sinh ra cac
     * tien to o ben trong luc index nen tim theo dau so moi dung. Khong ghi o day thi truong luon
     * rong va moi tra cu `phonePrefix` deu tra ve 0 ket qua.
     */
    phonePrefix: phone,
    state: customer.state,
    verifiedEmail: customer.verifiedEmail ?? false,
    haravanOrdersCount: customer.haravanOrdersCount ?? 0,
    haravanTotalSpent: customer.haravanTotalSpent ?? 0,
    beOrderCount: customer.beOrderCount ?? 0,
    beTotalSpent: customer.beTotalSpent ?? 0,
    lastOrderId: customer.lastOrderId,
    lastOrderName: customer.lastOrderName,
    orderIds: customer.orderIds,
    firstSeenAt: customer.firstSeenAt,
    lastSeenAt: customer.lastSeenAt,
    createdAt: customer.createdAt,
    updatedAt: customer.updatedAt,
    syncedAt: Date.now(),
  };
}

/**
 * Ket qua phan tich chuoi nguoi dung nhap.
 *
 * - `empty`: khong nhap gi, xem tat ca khach.
 * - `invalid`: nhap khong phu hop (it hon 3 so) — tra loi bang thong bao de hieu.
 * - `phone_suffix`: dung 3 so cuoi. **Day la truong hop chinh.**
 * - `phone_prefix`: nhap tu 4 so tro len, xem nhu go so dien thoai tu dau.
 * - `text`: co chu cai, tim theo ten / email.
 */
export type ParsedCustomerSearch =
  | { mode: 'empty'; raw: string }
  | { mode: 'invalid'; raw: string; reason: string }
  | { mode: 'phone_suffix'; raw: string; values: string[] }
  | { mode: 'phone_prefix'; raw: string; value: string }
  | { mode: 'text'; raw: string; value: string };

/**
 * Phan tich chuoi tim kiem cua nguoi dung thanh che do tra cua hai he so.
 *
 * Tien dao de ES va Mongo hieu y nhau, nen phan tich chi nam o day chu khong nham trong tung
 * service: doi mot lan la ca hai he cung doi, khong bao gio xay ra truong hop mot ben hieu
 * `633` la hau to con ben kia hieu la tim chuoi `633` bat ky dau.
 */
export function parseCustomerSearch(raw: string): ParsedCustomerSearch {
  const trimmed = (raw ?? '').trim();
  if (!trimmed) return { mode: 'empty', raw: trimmed };

  // Cho phep nhieu nhom sot bang dau phay hoac khoang trang, vd `633, 888`.
  const tokens = trimmed
    .split(/[\s,;]+/)
    .map((token) => token.trim())
    .filter(Boolean);

  const allDigits = tokens.every((token) => /^\d+$/.test(token));

  if (allDigits) {
    // Truong hop chinh: dung ba so cuoi, hoac nhieu nhom ba so cuoi.
    if (tokens.every((token) => token.length === PHONE_SUFFIX_LENGTH)) {
      return {
        mode: 'phone_suffix',
        raw: trimmed,
        values: Array.from(new Set(tokens)),
      };
    }

    const shortest = Math.min(...tokens.map((token) => token.length));
    if (shortest < PHONE_SUFFIX_LENGTH) {
      return {
        mode: 'invalid',
        raw: trimmed,
        reason:
          `Nhap it nhat ${PHONE_SUFFIX_LENGTH} chu so cuoi cua so dien thoai.`,
      };
    }

    // Tu 4 so tro len, coi nhu nguoi dung go so dien thoai tu dau.
    return { mode: 'phone_prefix', raw: trimmed, value: trimmed };
  }

  return { mode: 'text', raw: trimmed, value: trimmed };
}

/**
 * Chuan hoa dau vao cua che do nhieu hau to thanh mang `regex` cho MongoDB.
 *
 * Chi con chu so nen khong can escape; `633` thanh `/633$/`, khop dung so dien thoai **ket thuc**
 * bang 633 chu khong phai mot cum ba so nam o giua.
 */
export function toSuffixRegex(values: string[]): RegExp {
  return new RegExp(`(?:${values.join('|')})$`);
}
