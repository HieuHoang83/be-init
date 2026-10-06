/**
 * Test thu WEBHOOK KET NOI APP (khong phai webhook rieng tu).
 *
 *   node scripts/test-webhook-app.mjs [baseUrl]
 *
 * Mac dinh baseUrl = http://localhost:3000
 * Can app chay: npm run start:dev
 */
import { createHmac } from 'node:crypto';

const base = (process.argv[2] || 'http://localhost:3000').replace(/\/$/, '');
const url = `${base}/api/v1/webhooks/app`;

const SECRET = process.env.HARAVAN_APP_CLIENT_SECRET || 'local-app-secret';
const VERIFY_TOKEN = process.env.HARAVAN_APP_VERIFY_TOKEN || 'local-verify-token';
const ORG_ID = process.env.HARAVAN_ORG_ID || '123456';
const CHALLENGE = 'chao-haravan-123';

function sign(raw) {
  return createHmac('sha256', SECRET).update(raw).digest('base64');
}

async function step(name, fn, check) {
  console.log(`\n=== ${name} ===`);
  const res = await fn();
  const text = await res.text();
  console.log(`status: ${res.status}`);
  console.log(`body  : ${JSON.stringify(text)}`);
  if (check) console.log(check(res.status, text) ? 'PASS' : 'FAIL');
  return { status: res.status, text };
}

const payload = {
  org_id: Number(ORG_ID),
  topic: 'orders/create',
  data: { id: 987654321, name: '#DH-01' },
};
const raw = JSON.stringify(payload);

const ok = await step(
  '1. GET subscribe (mong doi 200 + raw hub.challenge)',
  () =>
    fetch(
      `${url}?hub.mode=subscribe&hub.verify_token=${encodeURIComponent(
        VERIFY_TOKEN,
      )}&hub.challenge=${CHALLENGE}&org_id=${ORG_ID}`,
    ),
  (status, text) => status === 200 && text === CHALLENGE,
);

await step(
  '2. GET subscribe sai verify_token (mong doi 401)',
  () =>
    fetch(
      `${url}?hub.mode=subscribe&hub.verify_token=SAI&hub.challenge=${CHALLENGE}&org_id=${ORG_ID}`,
    ),
  (status) => status === 401,
);

await step(
  '3. POST thong bao, HMAC dung (mong doi 200)',
  () =>
    fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Haravan-Hmacsha256': sign(raw),
        'X-Haravan-Retry': '0',
      },
      body: raw,
    }),
  (status) => status === 200,
);

await step(
  '4. POST thong bao, HMAC sai (mong doi 401)',
  () =>
    fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Haravan-Hmacsha256': 'sai-chu-ky',
      },
      body: raw,
    }),
  (status) => status === 401,
);

await step(
  '5. POST thong bao, thieu header (mong doi 401)',
  () =>
    fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: raw,
    }),
  (status) => status === 401,
);

console.log('\nXong. Nho: Harovan chi goi duoc HTTPS - test that tren local,');
console.log('can tunnel (cloudflared / ngrok / localtunnel) khi dang ky app that.');
