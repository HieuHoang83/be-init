/**
 * Đọc HMAC Haravan gửi và raw body trong logs/webhook.log, sau đó thử từng
 * secret để tìm giá trị khớp.
 *
 * Cách dùng:
 *   node scripts/check-webhook-secret.mjs                 # thử secret trong .env
 *   node scripts/check-webhook-secret.mjs abc def ghi     # thử thêm secret nhập vào
 *
 * Không sửa tệp hoặc gọi Haravan API; chỉ so sánh cục bộ.
 */
import { readFileSync } from 'node:fs';
import { createHmac, timingSafeEqual } from 'node:crypto';

const LOG = 'logs/webhook.log';
const HEADER = 'x-haravan-hmacsha256';

function readEnv() {
  const env = {};
  try {
    for (const line of readFileSync('.env', 'utf8').split('\n')) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m) env[m[1]] = m[2].trim();
    }
  } catch {}
  return env;
}

/** Lấy các yêu cầu gần nhất có mã 401, kèm nội dung gốc và chữ ký. */
function loadCaptured() {
  let lines;
  try {
    lines = readFileSync(LOG, 'utf8').trim().split('\n');
  } catch {
    console.error(`Khong doc duoc ${LOG}. Hay chay BE it nhat 1 lan truoc.`);
    process.exit(1);
  }

  const out = [];
  for (const line of lines) {
    let d;
    try {
      d = JSON.parse(line);
    } catch {
      continue;
    }
    const sig = d?.headers?.[HEADER];
    if (typeof sig !== 'string' || typeof d.raw !== 'string') continue;
    out.push({
      at: d.at,
      endpoint: d.endpoint,
      status: d.status,
      sig,
      raw: d.raw,
      endpointKind: d.kind,
      requestBodyBytes: Buffer.byteLength(d.raw, 'utf8'),
    });
  }
  return out;
}

function sign(secret, body) {
  return createHmac('sha256', secret).update(Buffer.from(body, 'utf8')).digest('base64');
}

function match(sigA, sigB) {
  const a = Buffer.from(sigA);
  const b = Buffer.from(sigB);
  return a.length === b.length && timingSafeEqual(a, b);
}

const env = readEnv();
const extra = process.argv.slice(2).filter(Boolean);

const candidates = [
  ['HARAVAN_WEBHOOK_SECRET', env.HARAVAN_WEBHOOK_SECRET],
  ['HARAVAN_APP_CLIENT_SECRET', env.HARAVAN_APP_CLIENT_SECRET],
  ['HARAVAN_APP_VERIFY_TOKEN', env.HARAVAN_APP_VERIFY_TOKEN],
  ['HARAVAN_ACCESS_TOKEN', env.HARAVAN_ACCESS_TOKEN],
  ...extra.map((s, i) => [`CLI #${i + 1}`, s]),
].filter(([, v]) => typeof v === 'string' && v.length > 0);

if (candidates.length === 0) {
  console.error('Khong co secret nao de thu.');
  process.exit(1);
}

const captured = loadCaptured();
if (captured.length === 0) {
  console.error(`Khong tim thay request nao co ${HEADER} trong ${LOG}.`);
  process.exit(1);
}

// Chỉ lấy yêu cầu gần nhất của mỗi loại endpoint để so sánh.
const latest = new Map();
for (const c of captured) latest.set(c.endpointKind, c);
const targets = [...latest.values()];

console.log(`Thu ${candidates.length} secret tren ${targets.length} request gan nhat:\n`);

let found = false;
for (const target of targets) {
  console.log(`--- ${target.endpoint}  (${target.at}, status ${target.status}) ---`);
  console.log(`    chu ky Haravan : ${target.sig}`);
  console.log(`    raw body       : ${target.requestBodyBytes} bytes\n`);

  for (const [name, secret] of candidates) {
    const computed = sign(secret, target.raw);
    const ok = match(target.sig, computed);
    const shown = secret.length > 12 ? `${secret.slice(0, 6)}...${secret.slice(-4)}` : secret;
    if (ok) found = true;
    console.log(
      `    ${ok ? 'KHOP  ' : 'khong '} ${name.padEnd(28)} ${shown.padEnd(16)} ${computed}`,
    );
  }
  console.log('');
}

console.log(found ? '=> Tim thay secret dung.' : '=> Khong secret nao khop.');
process.exit(found ? 0 : 2);
