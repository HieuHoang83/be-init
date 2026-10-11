/** Lo thao tac can lam tren Elasticsearch cho mot khach. */
export type PendingOp = 'index' | 'delete';

/**
 * Bo dem gom khach cho, dung chung giua moi tien trinh.
 *
 * Bo dem nam trong Redis chu khong phai trong RAM cua tien trinh, nen:
 *
 * 1. moi tien trinh deu thay cung mot lo khach;
 * 2. lo chua ghi xong con lai duoc sau khi may chet hay restart;
 * 3. khong con khoang thoi gian nao ma cong viec ghi bi thay the khi may chet (do chuyen lo sang
 *    key dang ghi bang lenh nguyen tu, xem `RedisPendingBuffer.drain`).
 *
 * Moi phuong thuc deu la viec dong bo hoac await ngan. `drain` rut lo theo cach nguyen tu va
 * lo rut ra phai con nguyen cho den khi ghi xong hoac duoc tra lai — `run()` cua
 * `CustomerIndexBatcher` chay tiep nen khong duoc de lo bi bo nho trong luc do.
 */
export interface PendingBuffer {
  /** Ghi mot khach vao lo. Tra ve so khach hien dang cho (khong tinh moc thoi gian). */
  add(id: string, op: PendingOp): Promise<number>;

  /** Rut nguyen lo hien tai; lo rong thi tra ve mang rong. */
  drain(): Promise<Array<[string, PendingOp]>>;

  /** Tra lo da rut lai vao lo (dung khi ghi that bai). */
  restore(batch: Array<[string, PendingOp]>): Promise<void>;

  /** So khach dang cho. */
  size(): Promise<number>;

  /**
   * Bat lich chay. `onDue` duoc goi khi lo du `batchSize` hoac da het `flushIntervalMs`.
   *
   * Bo dem tu quyet dinh khi nao la het han vi no nam o noi luu han — day la Redis nen phai
   * nhac quet thay vi dat hen gio trong RAM.
   */
  start(onDue: () => void): void;

  /** Tat lich chay. */
  stop(): void;

  /** Dong ket noi Redis. */
  close(): void;
}
