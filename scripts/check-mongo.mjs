import mongoose from 'mongoose';
import fs from 'node:fs';

const env = Object.fromEntries(
  fs
    .readFileSync('.env', 'utf8')
    .split(/\r?\n/)
    .map((line) => line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/))
    .filter(Boolean)
    .map(([, key, value]) => [key, value.replace(/^(['"])(.*)\1$/, '$2')]),
);

const dbName = env.MONGODB_DB_NAME || 'be_init';
let uri = env.MONGODB_URI;

if (!uri && env.MONGODB_USERNAME && env.MONGODB_PASSWORD && env.MONGODB_CLUSTER) {
  const user = encodeURIComponent(env.MONGODB_USERNAME);
  const password = encodeURIComponent(env.MONGODB_PASSWORD);
  uri = `mongodb+srv://${user}:${password}@${env.MONGODB_CLUSTER}/${dbName}`;
}

if (!uri) {
  throw new Error('Set MONGODB_URI or MONGODB_USERNAME, MONGODB_PASSWORD, and MONGODB_CLUSTER in .env');
}

if (!/^mongodb(\+srv)?:\/\/[^/]+\/[^/?]+/.test(uri)) {
  uri = `${uri.replace(/\/+$/, '')}/${dbName}`;
}

try {
  await mongoose.connect(uri, {
    dbName,
    serverSelectionTimeoutMS: 15000,
  });
  console.log(
    'OK, collections:',
    (await mongoose.connection.db.collections())
      .map((collection) => collection.name)
      .join(', ') || '(chua co)',
  );
  await mongoose.disconnect();
} catch (e) {
  console.log('\nFAIL:', e.name);
  console.log(String(e.message).split('\n').slice(0, 6).join('\n'));
}
