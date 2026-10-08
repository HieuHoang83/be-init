/**
 * Kiem tra logic gop dong don dat hang bang chinh ham cua FE.
 * Chay: npx ts-node --compiler-options '{"module":"commonjs"}' check-po-rows.ts
 */
import {
  purchaseOrderRows,
  purchaseOrderRowStatus,
  purchaseOrderTotals,
  type PurchaseOrderDocument,
} from '../fe-QLDA/src/services/api/inventory-documents';

const document = {
  id: 1001262443,
  line_item: {
    received_items: [
      { id: 1, product_id: 10, product_variant_id: 100, product_name: 'Cafe Muoi', quantity: 3, cost_amount: 90000, receive_id: 500, receive_date: '2026-10-07T02:00:00Z' },
      { id: 2, product_id: 11, product_variant_id: 101, product_name: 'Banh Mi', quantity: 10, cost_amount: 500000, receive_id: 501, receive_date: '2026-10-08T02:00:00Z' },
    ],
    not_received_items: [
      { id: 3, product_id: 10, product_variant_id: 100, product_name: 'Cafe Muoi', quantity: 7, cost_amount: 210000 },
      { id: 4, product_id: 12, product_variant_id: 102, product_name: 'Tra Sen', quantity: 5, cost_amount: 100000 },
    ],
  },
} as unknown as PurchaseOrderDocument;

const rows = purchaseOrderRows(document);
const totals = purchaseOrderTotals(document);

console.log('SO DONG SAU KHI GOP:', rows.length);
for (const row of rows) {
  console.log(
    `  ${row.product_name}: da nhan ${row.receivedQuantity}/${row.totalQuantity} ` +
      `(${purchaseOrderRowStatus(row)}), gia ${row.totalCost}, so lan nhat ${row.receiveCount}`,
  );
}

console.log('\nTONG:', JSON.stringify(totals));

const checks: Array<[string, boolean]> = [
  ['Gop 3 dong goc thanh 3 dong san pham', rows.length === 3],
  ['Cafe Muoi 3 da nhan + 7 cho = 10 tong', rows[0].totalQuantity === 10 && rows[0].receivedQuantity === 3 && rows[0].pendingQuantity === 7],
  ['Cafe Muoi nhap mot phan', purchaseOrderRowStatus(rows[0]) === 'partial'],
  ['Banh Mi nhan het -> received', rows[1].receivedQuantity === 10 && purchaseOrderRowStatus(rows[1]) === 'received'],
  ['Tra Sen chua nhap gi -> pending', purchaseOrderRowStatus(rows[2]) === 'pending' && rows[2].receivedQuantity === 0],
  ['Chi dem 1 lan nhat khi 1 dong nhat', rows[0].receiveCount === 1],
  ['Tong SL = 10 + 10 + 5 = 25', totals.totalQuantity === 25],
  ['Tong da nhan = 3 + 10 = 13', totals.receivedQuantity === 13],
  ['Tong cho nhan = 7 + 5 = 12', totals.pendingQuantity === 12],
  ['Gia don gop dung', rows[0].totalCost === 90000 + 210000],
];

console.log('');
let failed = 0;
for (const [name, ok] of checks) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok) failed += 1;
}
console.log(`\n${checks.length - failed}/${checks.length} kiem tra dat.`);
process.exit(failed ? 1 : 0);
