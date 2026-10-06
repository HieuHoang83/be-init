/**
 * Doi authorization code lay access_token, roi tu ghi vao .env.
 *
 *   node scripts/haravan-token.mjs <authorization-code>
 *
 * Code chi dung MOT LAN va nganh -> neu bao invalid_grant, lay code moi
 * va chay lai ngay.
 */
import { readFileSync, writeFileSync } from 'node:fs';

const TOKEN_URL = 'https://accounts.haravan.com/connect/token';

const env = {};
for (const line of readFileSync('.env', 'utf8').split('\n')) {
  const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
  if (m) env[m[1]] = m[2].trim();
}

const code = process.argv[2] || env.HARAVAN_AUTHORIZATION_CODE;
const clientId = env.HARAVAN_CLIENT_ID;
const clientSecret = env.HARAVAN_CLIENT_SECRET;
const redirectUri = env.HARAVAN_REDIRECT_URI;

if (!code) {
  console.error(
    'Thieu authorization code.\n' +
      '  Lay code moi tu trang authorize cua app roi chay:\n' +
      '    node scripts/haravan-token.mjs <authorization-code>',
  );
  process.exit(1);
}

for (const [name, value] of Object.entries({ HARAVAN_CLIENT_ID: clientId, HARAVAN_CLIENT_SECRET: clientSecret, HARAVAN_REDIRECT_URI: redirectUri })) {
  if (!value) {
    console.error(`Thieu ${name} trong .env`);
    process.exit(1);
  }
}

const body = new URLSearchParams({
  grant_type: 'authorization_code',
  client_id: clientId,
  client_secret: clientSecret,
  code,
  redirect_uri: redirectUri,
});

console.log(`POST ${TOKEN_URL}`);
console.log(`  client_id     : ${clientId}`);
console.log(`  redirect_uri  : ${redirectUri}`);
console.log(`  code          : ${code.slice(0, 6)}...${code.slice(-4)}\n`);

const res = await fetch(TOKEN_URL, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body,
});

const text = await res.text();
let json;
try {
  json = JSON.parse(text);
} catch {
  console.log(`HTTP ${res.status}\n${text.slice(0, 500)}`);
  process.exit(1);
}

if (!res.ok || json.error) {
  console.log(`HTTP ${res.status}  ERROR`);
  console.log(JSON.stringify(json, null, 2));
  if (json.error === 'invalid_grant') {
    console.log(
      '\ninvalid_grant = code sai, het han, da dung, hoac redirect_uri/client_id khong khop.\n' +
        'Kiem tra lai: code lay tu app nao, va redirect_uri co giong luc authorize khong.',
    );
  }
  process.exit(1);
}

const token = json.access_token;
if (!token) {
  console.log(`HTTP ${res.status}  Khong co access_token trong response`);
  process.exit(1);
}

let updated = readFileSync('.env', 'utf8');
updated = updated.replace(/^HARAVAN_ACCESS_TOKEN=.*$/m, `HARAVAN_ACCESS_TOKEN=${token}`);

if (json.refresh_token) {
  updated = updated.replace(
    /^HARAVAN_REFRESH_TOKEN=.*$/m,
    `HARAVAN_REFRESH_TOKEN=${json.refresh_token}`,
  );
  if (!/^HARAVAN_REFRESH_TOKEN=/m.test(updated)) {
    updated += `HARAVAN_REFRESH_TOKEN=${json.refresh_token}\n`;
  }
}

writeFileSync('.env', updated, 'utf8');

console.log(`HTTP ${res.status}  OK`);
console.log(`  token_type : ${json.token_type}`);
console.log(`  expires_in : ${json.expires_in ?? '-'}`);
console.log(`  scope      : ${json.scope ?? '-'}`);
console.log(`\nDa ghi HARAVAN_ACCESS_TOKEN vao .env (${token.slice(0, 8)}...)`);
