/**
 * Dọn đơn rác do webhook không lọc topic.
 *
 * Mọi topic khác `orders/...` (customers, products, inventory, locations)
 * đều bị coi nhầm là đơn hàng vì body của chúng cũng có trường `id`.
 * Đơn tạo ra như vậy không có sản phẩm, không có tổng tiền và
 * `orderName` trùng bằng `haravanOrderId`.
 *
 * Chạy thử trước (mặc định chỉ báo cáo):
 *   node scripts/cleanup-garbage-orders.mjs
 * Xác nhận rồi mới xoá thật:
 *   node scripts/cleanup-garbage-orders.mjs --apply
 */
import 'dotenv/config';
import mongoose from 'mongoose';

const APPLY = process.argv.includes('--apply');

await mongoose.connect(process.env.MONGODB_URI, {
  dbName: process.env.MONGODB_DB_NAME,
});
const db = mongoose.connection.db;
const orders = db.collection('orders');
const events = db.collection('webhook_events');

// ID đơn từng xuất hiện trong webhook `orders/*` -> không được đụng tới.
const realIds = new Set(
  (
    await events
      .aggregate([
        { $match: { topic: { $regex: '^orders/' } } },
        { $group: { _id: '$haravanOrderId' } },
      ])
      .toArray()
  )
    .map((r) => r._id)
    .filter(Boolean),
);

const all = await orders.find({}).toArray();
const garbage = all.filter((o) => {
  // Đơn thật luôn có số đơn dạng #10007. Đơn rác được sinh từ payload rỗng
  // nên `orderName` lại chính là `haravanOrderId` (một con số dài).
  const name = String(o.orderName ?? o.orderNumber ?? '');
  return !/^#?\d{4,7}$/.test(name);
});

console.log(`Tong don: ${all.length}`);
console.log(`Don rac se xoa: ${garbage.length}`);
console.log(`Giu lai: ${all.length - garbage.length}`);

if (!APPLY) {
  console.log('\n-- Chay o che do xem. Them --apply de thuc su xoa.');
  console.log(
    JSON.stringify(
      garbage.slice(0, 10).map((o) => ({
        id: o.haravanOrderId,
        status: o.status,
        createdAt: o.createdAt,
      })),
      null,
      2,
    ),
  );
  await mongoose.disconnect();
  process.exit(0);
}

const ids = garbage.map((o) => o._id);

// Sao luu de chay lai duoc neu can.
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const backupFile = `logs/backup-garbage-orders-${stamp}.json`;
await import('node:fs/promises').then((fs) =>
  fs.mkdir('logs', { recursive: true }).then(() =>
    fs.writeFile(backupFile, JSON.stringify(garbage, null, 2), 'utf8'),
  ),
);
console.log(`\nDa backup ${garbage.length} don vao ${backupFile}`);

const result = await orders.deleteMany({ _id: { $in: ids } });

// Dọn luôn action/event của các đơn rác để nhật ký không còn nội dung rác.
const orderIds = garbage.map((o) => o.haravanOrderId);
const actions = await db
  .collection('order_actions')
  .deleteMany({ haravanOrderId: { $in: orderIds } });
const orderEvents = await db
  .collection('order_events')
  .deleteMany({ haravanOrderId: { $in: orderIds } });

console.log(`\nDa xoa ${result.deletedCount} don rac.`);
console.log(`Da xoa ${actions.deletedCount} order_actions.`);
console.log(`Da xoa ${orderEvents.deletedCount} order_events.`);

const left = await orders.countDocuments();
console.log(`Con lai ${left} don.`);

await mongoose.disconnect();
