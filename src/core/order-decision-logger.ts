import { appendFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Log dang TEXT de doc nhanh: ten don, thu tu don, khach va ket qua xu ly.
 * JSON chi tiet van nam o logs/webhook.log.
 */
const LOG_DIR = join(process.cwd(), 'logs');
const ORDER_LOG = join(LOG_DIR, 'order-decision.log');

function line(): string {
  return new Date().toLocaleString('vi-VN', { hour12: false });
}

function pad(value: unknown, width: number): string {
  const text =
    value === null || value === undefined || value === '' ? '-' : String(value);
  return text.length >= width ? text.slice(0, width) : text.padEnd(width, ' ');
}

/**
 * @param r.khachCu null = chua xac dinh, false = khach moi, true = khach cu
 * @param r.soDonTruoc so don truoc don nay, null neu khong xac dinh duoc
 */
export interface OrderDecisionLog {
  endpoint: string;
  topic: string;
  orgId: number | null;
  orderId: number | null;
  orderName?: string | null;
  totalPrice?: number | null;
  customerName?: string | null;
  customerPhone?: string | null;
  customerEmail?: string | null;
  khachCu?: boolean | null;
  soDonTruoc?: number | null;
  chiTieuTruoc?: number | null;
  confirmed?: boolean;
  confirmedStatus?: string | null;
  financialStatus?: string | null;
  skipReason?: string | null;
  isTest?: boolean;
  error?: string | null;
}

export function logOrderDecision(r: OrderDecisionLog): void {
  const nhan =
    r.khachCu === true
      ? 'KHACH CU'
      : r.khachCu === false
      ? 'KHACH MOI'
      : 'CHUA BIET';

  const ketQua = r.isTest
    ? 'PAYLOAD TEST'
    : r.error
    ? `LOI: ${r.error}`
    : r.confirmed
    ? 'DA AUTO-CONFIRM'
    : `BO QUA (${r.skipReason ?? 'khong ro'})`;
  const thuTuDon =
    r.soDonTruoc === null || r.soDonTruoc === undefined
      ? 'KHONG XAC DINH'
      : r.soDonTruoc === 0
      ? 'DON DAU TIEN'
      : `DON THU ${r.soDonTruoc + 1} (${r.soDonTruoc} truoc)`;

  const dong = [
    line(),
    pad(r.endpoint, 34),
    pad(r.topic, 14),
    pad(r.orderName ?? r.orderId, 14),
    pad(r.orderId, 14),
    pad(r.customerName, 22),
    pad(r.customerPhone, 12),
    pad(thuTuDon, 32),
    pad(nhan, 14),
    pad(ketQua, 34),
    r.totalPrice ? `${r.totalPrice} VND` : '-',
    r.confirmedStatus ? `confirmed=${r.confirmedStatus}` : '',
  ]
    .filter(Boolean)
    .join(' | ');

  mkdirSync(LOG_DIR, { recursive: true });
  appendFileSync(ORDER_LOG, dong + '\n', 'utf8');
}
