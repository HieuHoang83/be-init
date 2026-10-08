import 'dotenv/config';
import mongoose from 'mongoose';

await mongoose.connect(process.env.MONGODB_URI, {
  dbName: process.env.MONGODB_DB_NAME,
});
const db = mongoose.connection.db;
const orders = db.collection('orders');
const events = db.collection('webhook_events');

const all = await orders.find({}).sort({ createdAt: -1 }).toArray();
console.log('TONG DON TRONG MONGODB:', all.length);

const hasItems = (o) => Array.isArray(o.lineItems) && o.lineItems.length > 0;
const good = all.filter(hasItems);
const bad = all.filter((o) => !hasItems(o));
console.log('  - Co san pham :', good.length);
console.log('  - KHONG co san pham (rac):', bad.length);

// Don rac co `orderName` chinh la ID -> dau hieu payload rong
const nameIsId = bad.filter((o) => String(o.orderName) === String(o.haravanOrderId));
console.log('  - Rac & orderName == haravanOrderId:', nameIsId.length);

// Topic webhook sinh ra don rac
const badIds = bad.map((o) => o.haravanOrderId);
const topicMap = await events
  .aggregate([
    { $match: { haravanOrderId: { $in: badIds } } },
    { $group: { _id: { id: '$haravanOrderId', topic: '$topic' }, n: { $sum: 1 } } },
  ])
  .toArray();

const byId = new Map();
for (const t of topicMap) {
  if (!byId.has(t._id.id)) byId.set(t._id.id, {});
  byId.get(t._id.id)[t._id.topic] = t.n;
}

const topicsCausing = new Map();
for (const topics of byId.values()) {
  for (const topic of Object.keys(topics)) {
    topicsCausing.set(topic, (topicsCausing.get(topic) ?? 0) + 1);
  }
}
console.log('\nTOPIC NAO GHI RA DON RAC:');
console.log(
  JSON.stringify(
    [...topicsCausing.entries()].sort((a, b) => b[1] - a[1]).map(([t, n]) => ({ topic: t, don: n })),
    null,
    2,
  ),
);

console.log('\nCHI TIET DON RAC (20 dong dau):');
console.log(
  bad.slice(0, 20)
    .map((o) => ({
      id: o.haravanOrderId,
      status: o.status,
      total: o.totalPrice ?? null,
      created: o.createdAt?.toISOString?.().slice(0, 16),
      topics: byId.get(o.haravanOrderId) ?? 'khong ro',
    })),
);

// Don co san pham nhung ID trùng với don rac -> trung ID bat thuong
const goodIds = new Set(good.map((o) => o.haravanOrderId));
const overlap = badIds.filter((id) => goodIds.has(id));
console.log('\nID vua la don rac vua la don tot:', overlap.length);

// Trung ID don trong cùng org?
const dupIds = await orders
  .aggregate([
    { $group: { _id: { orgId: '$orgId', id: '$haravanOrderId' }, n: { $sum: 1 } } },
    { $match: { n: { $gt: 1 } } },
  ])
  .toArray();
console.log('ID bi ghi trung (cung org):', dupIds.length, JSON.stringify(dupIds.slice(0, 5)));

// Đơn Haravan có topic orders/* nhưng chưa được lưu đúng vào DB
const realEvents = await events
  .aggregate([
    { $match: { topic: { $regex: '^orders/' } } },
    { $group: { _id: '$haravanOrderId', topics: { $addToSet: '$topic' }, n: { $sum: 1 } } },
    { $sort: { n: -1 } },
  ])
  .toArray();

const storedIds = new Set(all.map((o) => o.haravanOrderId));
const missing = realEvents.filter((e) => e._id && !storedIds.has(e._id));
console.log('\nDON CO TOPIC orders/* TRONG WEBHOOK:', realEvents.length);
console.log('  - Da co trong DB orders:', realEvents.length - missing.length);
console.log('  - THIEU trong DB orders:', missing.length);
console.log('  - Topic cua nhung don thieu:',
  JSON.stringify(
    missing.flatMap((m) => m.topics.map((t) => ({ topic: t, n: m.n }))).slice(0, 10),
  ));

// Phân bổ topic của các đơn đã lưu đúng
const goodIdsList = good.map((o) => o.haravanOrderId);
const goodTopics = await events
  .aggregate([
    { $match: { haravanOrderId: { $in: goodIdsList } } },
    { $group: { _id: '$topic', n: { $sum: 1 } } },
    { $sort: { n: -1 } },
  ])
  .toArray();
console.log('\nTOPIC TAO RA 23 DON THAT:', JSON.stringify(goodTopics));

const failedJobs = await db
  .collection('jobs')
  .find({ status: 'failed' })
  .project({ payload: 1, error: 1, attempts: 1 })
  .toArray();
console.log('\nJOB CHET:', failedJobs.length);
const failedIds = [...new Set(failedJobs.map((j) => j.payload?.haravanOrderId))].filter(Boolean);
console.log('  - Don ID bi job chet:', JSON.stringify(failedIds));
console.log('  - Trong do chua co trong DB:', JSON.stringify(failedIds.filter((id) => !storedIds.has(id))));
const errKinds = {};
for (const j of failedJobs) {
  const key = String(j.error).slice(0, 70);
  errKinds[key] = (errKinds[key] ?? 0) + 1;
}
console.log('  - Loai loi:', JSON.stringify(errKinds, null, 2));

const MIN = 10000;
const MAX = 10034;
const inRange = all.filter((o) => o.haravanOrderId >= MIN && o.haravanOrderId <= MAX);
const outRange = all.filter((o) => o.haravanOrderId < MIN || o.haravanOrderId > MAX);
console.log(`\nTRONG KHOANG ${MIN}-${MAX}:`, inRange.length);
console.log(`   - co san pham:`, inRange.filter(hasItems).length);
console.log(`   - rong:`, inRange.filter((o) => !hasItems(o)).length);
console.log('   IDs:', JSON.stringify(inRange.map((o) => o.haravanOrderId).sort((a, b) => a - b)));

console.log(`\nNGOAI KHOANG:`, outRange.length);
console.log('   - co san pham:', outRange.filter(hasItems).length);
console.log('   - rong:', outRange.filter((o) => !hasItems(o)).length);
console.log('   mau co san pham:', JSON.stringify(
  outRange.filter(hasItems).slice(0, 5).map((o) => ({ id: o.haravanOrderId, status: o.status })),
));

const byOrg = await orders.aggregate([
  { $group: { _id: '$orgId', n: { $sum: 1 }, min: { $min: '$haravanOrderId' }, max: { $max: '$haravanOrderId' } } },
]).toArray();
console.log('\nTHEO ORG:', JSON.stringify(byOrg, null, 2));

const eventsByOrg = await events.aggregate([
  { $group: { _id: '$orgId', n: { $sum: 1 }, minOrder: { $min: '$haravanOrderId' }, maxOrder: { $max: '$haravanOrderId' } } },
]).toArray();
console.log('\nWEBHOOK THEO ORG:', JSON.stringify(eventsByOrg, null, 2));

// Don co san pham: topic nao tao ra
const goodIds2 = all.filter(hasItems).map((o) => o.haravanOrderId);
const goodTopicRows = await events.aggregate([
  { $match: { haravanOrderId: { $in: goodIds2 } } },
  { $group: { _id: { orgId: '$orgId', topic: '$topic' }, n: { $sum: 1 } } },
]).toArray();
console.log('\nTOPIC CUA DON CO SAN PHAM:', JSON.stringify(goodTopicRows, null, 2));

console.log('\nDON CO SAN PHAM (id | name | orderNumber):');
for (const o of all.filter(hasItems).sort((a, b) => a.haravanOrderId - b.haravanOrderId)) {
  console.log(`  ${o.haravanOrderId} | name=${o.orderName} | no=${o.orderNumber} | total=${o.totalPrice} | status=${o.status}`);
}

await mongoose.disconnect();
