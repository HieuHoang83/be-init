/**
 * Đổi index unique của `customers` từ `sparse` sang `partial`.
 *
 * Lý do: `sparse` bỏ qua document thiếu field nhưng KHÔNG bỏ qua field = null.
 * Khách không có email được lưu thành `email: null`, nên chỉ một khách duy nhất
 * được phép tồn tại -> mọi khách vô danh tiếp theo đều nhận
 * E11000 duplicate key (orgId + null) và job chết vĩnh viễn.
 *
 * Xem trước:
 *   node scripts/migrate-customer-indexes.mjs
 * Thực thi:
 *   node scripts/migrate-customer-indexes.mjs --apply
 */
import 'dotenv/config';
import mongoose from 'mongoose';

const APPLY = process.argv.includes('--apply');

await mongoose.connect(process.env.MONGODB_URI, {
  dbName: process.env.MONGODB_DB_NAME,
});
const coll = mongoose.connection.db.collection('customers');

// Giá trị null/số rác sẽ vi phạm partial index -> cần dọn trước.
const badEmail = await coll.countDocuments({
  email: { $not: { $type: 'string' } },
});
const badPhone = await coll.countDocuments({
  phone: { $not: { $type: 'string' } },
});
const emailStrings = await coll.countDocuments({ email: { $type: 'string' } });
const phoneStrings = await coll.countDocuments({ phone: { $type: 'string' } });

console.log('TRUOC khi migrate:');
console.log('  email khong phai string:', badEmail);
console.log('  phone khong phai string:', badPhone);
console.log('  email la string:', emailStrings);
console.log('  phone la string:', phoneStrings);

if (!APPLY) {
  console.log('\nIndex hien tai:');
  for (const idx of await coll.indexes()) {
    if (idx.name === 'orgId_1_email_1' || idx.name === 'orgId_1_phone_1') {
      console.log(' ', idx.name, JSON.stringify(idx));
    }
  }
  console.log('\n-- Them --apply de migrate.');
  await mongoose.disconnect();
  process.exit(0);
}

// Bỏ field rác để partial index không bị vi phạm.
await coll.updateMany(
  { email: { $not: { $type: 'string' } } },
  { $unset: { email: '' } },
);
await coll.updateMany(
  { phone: { $not: { $type: 'string' } } },
  { $unset: { phone: '' } },
);

await coll.dropIndex('orgId_1_email_1').catch(() => {});
await coll.dropIndex('orgId_1_phone_1').catch(() => {});
await coll.createIndex(
  { orgId: 1, email: 1 },
  {
    name: 'orgId_1_email_1',
    unique: true,
    partialFilterExpression: { email: { $type: 'string' } },
  },
);
await coll.createIndex(
  { orgId: 1, phone: 1 },
  {
    name: 'orgId_1_phone_1',
    unique: true,
    partialFilterExpression: { phone: { $type: 'string' } },
  },
);

console.log('\nSAU khi migrate:');
for (const idx of await coll.indexes()) {
  if (idx.name === 'orgId_1_email_1' || idx.name === 'orgId_1_phone_1') {
    console.log(' ', idx.name, JSON.stringify(idx));
  }
}

await mongoose.disconnect();
