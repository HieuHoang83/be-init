import mongoose from 'mongoose';
import fs from 'node:fs';

const text = fs.readFileSync('.env','utf8') + '\n' + fs.readFileSync('atlas-credentials.env','utf8');
const get = k => { const m = text.match(new RegExp(`^${k}=(.+)$`,'m')); return m ? m[1].trim().replace(/^"|"$/g,'') : undefined; };

const dbName = get('MONGODB_DB_NAME') || 'be_init';
const user = get('MONGODB_USERNAME');
const pass = get('MONGODB_PASSWORD');
const host = 'cluster0.a7gfn5l.mongodb.net';
const uri = `mongodb+srv://${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${host}/${dbName}`;

console.log('user   :', user);
console.log('pass len:', (pass||'').length);
console.log('host   :', host, '| db:', dbName);
console.log('pass co ky tu dac biet?', /[^A-Za-z0-9]/.test(pass||'') ? 'CO' : 'khong');

try {
  await mongoose.connect(uri, { serverSelectionTimeoutMS: 15000 });
  console.log('OK, collections:', (await mongoose.connection.db.collections()).map(c=>c.name).join(', ') || '(chua co)');
  await mongoose.disconnect();
} catch (e) {
  console.log('\nFAIL:', e.name);
  console.log(String(e.message).split('\n').slice(0,6).join('\n'));
}
