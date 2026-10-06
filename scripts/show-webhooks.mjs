/**
 * Đọc logs/webhook.log và nhóm theo loại luồng:
 *   - verify_token: GET có hub.* để xác thực ứng dụng.
 *   - event_notification: POST có HMAC, là thông báo đơn hàng.
 *   - hmac_rejected: POST bị từ chối với mã 401.
 *   - oauth_callback: GET /webhooks/callback?code=...
 *
 *   node scripts/show-webhooks.mjs            # 30 dòng gần nhất
 *   node scripts/show-webhooks.mjs 100        # 100 dòng
 *   node scripts/show-webhooks.mjs verify_token
 */
import { readFileSync } from 'node:fs';

const LOG = 'logs/webhook.log';

let lines;
try {
  lines = readFileSync(LOG, 'utf8').trim().split('\n');
} catch {
  console.error(`Không đọc được ${LOG}`);
  process.exit(1);
}

const rows = lines
  .map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return null;
    }
  })
  .filter(Boolean);

const filter = process.argv[3];
const limit = Number(process.argv[2]) || 30;

const selected = (filter ? rows.filter((r) => r.flow === filter) : rows).slice(-limit);

const FLOW_LABEL = {
  verify_token: 'VERIFY TOKEN',
  event_notification: 'EVENT',
  hmac_rejected: 'TU CHOI 401',
  oauth_callback: 'OAUTH',
};

console.log(
  `\nTong ${rows.length} dong | verify_token=${rows.filter((r) => r.flow === 'verify_token').length}` +
    ` | event=${rows.filter((r) => r.flow === 'event_notification').length}` +
    ` | 401=${rows.filter((r) => r.flow === 'hmac_rejected').length}` +
    ` | oauth=${rows.filter((r) => r.flow === 'oauth_callback').length}\n`,
);

console.log(
  ['time'.padEnd(9), 'flow'.padEnd(10), 'endpoint'.padEnd(32), 'topic'.padEnd(16), 'order', 'note'].join(
    ' | ',
  ),
);

for (const r of selected) {
  const note =
    r.result?.outcome ??
    r.result?.decision ??
    (r.error ? `LOI: ${r.error}` : '');
  console.log(
    [
      r.at.slice(11, 23),
      (FLOW_LABEL[r.flow] ?? r.flow ?? '-').padEnd(10),
      String(r.endpoint ?? '-').replace('/api/v1/', '').padEnd(32),
      String(r.topic ?? '-').slice(0, 15).padEnd(16),
      String(r.haravanOrderId ?? '-'),
      String(note).slice(0, 44),
    ].join(' | '),
  );
}

console.log('');
