# LUỒNG VẬN HÀNH CỦA HỆ THỐNG JOB (Webhook → Queue → Worker)

> Tài liệu mô tả chi tiết cách một sự kiện webhook của Haravan đi qua hệ thống và
> trở thành một `job` được xử lý bất đồng bộ.
> Nguồn code đối chiếu được ghi kèm theo từng mục (`file:line`).

---
 ...
## 1. Tổng quan kiến trúc

```
                        ┌──────────────────────────────────────────────┐
                        │              NestJS Application              │
                        │                                              │
 Haravan ──POST HMAC──▶ │  WebhookPrivateController  ─┐                │
                        │  WebhookAppController      ─┼─▶ webhook_events│──┐
                        │  OrderController (replay)  ─┘   (MongoDB)     │  │ payload gốc
                        │                                │             │  │
                        │                                ▼             │  │
                        │                          JobQueue.enqueue()  │  │
                        │                                │             │  │
                        │                                ▼             │  │
                        │                     jobs (MongoDB)           │  │
                        │                        ▲    │                │  │
                        │      claim/heartbeat/  │    │ claim (nguyên tử)│ │
                        │      complete/fail     │    ▼                │  │
                        │                  JobWorker (vòng lặp poll)   │  │
                        │                                │ dispatch    │  │
                        │                                ▼             │  │
                        │                        OrderWorker           │◀─┘
                        │                     (đọc lại payload)        │
                        │                                │             │
                        │                                ▼             │
                        │      OrderService.processIncomingOrder()     │
                        │        └─ evaluate rule ─▶ confirmOrder()    │
                        │                                │             │
                        │                                ▼             │
                        │                    Haravan Omni API (retry)  │
                        └──────────────────────────────────────────────┘
```

**Nguyên tắc chính:** HTTP controller chỉ *kiểm tra chữ ký → lưu payload → tạo job → trả 200 ngay*.
Toàn bộ việc gọi API, tính rule, ghi đơn hàng nằm ở worker nền.

---

## 2. Thành phần và file code

| Vai trò | File | Nhận xét |
|---|---|---|
| Interface hàng đợi (DI token) | `src/queue/queue.service.ts` | abstract `JobQueue`, `JOB_NAMES`, `QueueStats` |
| Triển khai hàng đợi MongoDB | `src/queue/mongo-job-queue.service.ts` | enqueue/claim/heartbeat/complete/fail/reclaim/ULID |
| Vòng lặp worker | `src/queue/job.worker.ts` | `pump() → execute() → reclaim()` |
| Schema công việc | `src/queue/job.entity.ts` | collection `jobs`, 4 index |
| DI module hàng đợi | `src/queue/queue.module.ts` | `{ provide: JobQueue, useClass: MongoJobQueue }` |
| Handler xử lý đơn | `src/order/order.worker.ts` | `registerHandler('order.created', …)` |
| Business rule + gọi API | `src/order/order.service.ts` | `processIncomingOrder`, `confirmOrder` |
| Webhook riêng tư | `src/webhook-private/webhook-private.controller.ts` | `POST /api/v1/webhooks/haravan` |
| Webhook ứng dụng | `src/webhook-app/webhook-app.controller.ts` | `GET` (subscribe) + `POST` (event) |
| Xác thực HMAC | `src/core/webhook-hmac.guard.ts` + `*.guard.ts` | kế thừa `HmacGuard` |
| Lưu payload webhook | `src/webhook-private/webhook-private.service.ts` | `record()`, `markStatus()`, `extractOrderPayload()` |
| Replay thủ công | `src/order/order.controller.ts:397` | `POST /orders/webhooks/:eventId/replay` |
| Thống kê queue | `src/order/order.controller.ts:332` | `GET /orders/queue` |
| Cấu hình | `src/config.ts:126-144` | `QueueConfig` |

> **Quan trọng:** có đúng **một** loại job đang được đăng ký handler:
> `order.created` (`JOB_NAMES.ORDER_CREATED`). Hai hằng `order.confirm` và
> `order.sync_customer` được khai báo nhưng **chưa có handler** — `enqueue()` sẽ
> ném lỗi nếu gọi (`mongo-job-queue.service.ts:108`).

---

## 3. Cấu hình vận hành (`QueueConfig`)

Đọc từ `src/config.ts:126-144`, giá trị mặc định khi `.env` không khai báo
(file `.env` hiện tại **không** đặt biến nào cho queue ⇒ dùng mặc định):

| Biến môi trường | Khóa | Mặc định | Ý nghĩa |
|---|---|---|---|
| `HARAVAN_QUEUE_CONCURRENCY` | `concurrency` | **5** | Số job chạy đồng thời **trong 1 tiến trình** |
| `HARAVAN_QUEUE_MAX_ATTEMPTS` | `maxAttempts` | **3** | Số lần thử tối đa cho mỗi job |
| `HARAVAN_QUEUE_BACKOFF_BASE_MS` | `backoffBaseMs` | **1000** | Thời gian chờ cơ sở |
| `HARAVAN_QUEUE_BACKOFF_MAX_MS` | `backoffMaxMs` | **30000** | Khoảng chờ tối đa |
| `JOB_QUEUE_POLL_INTERVAL_MS` | `pollIntervalMs` | **1000** | Chu kỳ quét job mới |
| `JOB_QUEUE_HEARTBEAT_INTERVAL_MS` | `heartbeatIntervalMs` | **4000** | Chu kỳ gia hạn `heartbeatAt` |
| `JOB_QUEUE_LEASE_MS` | `leaseMs` | **90000** (90s) | Thời hạn giữ job; quá hạn bị thu hồi |
| `JOB_QUEUE_RECLAIM_INTERVAL_MS` | `reclaimIntervalMs` | **300000** (5 phút) | Chu kỳ quét job hết hạn giữ |
| `JOB_QUEUE_ENABLED` | `enabled` | **true** (`!== 'false'`) | Bật/tắt worker |

`workerId = ${HOSTNAME ?? 'worker'}-${process.pid}` (`mongo-job-queue.service.ts:102`)
→ mỗi tiến trình/pod có định danh riêng, dùng để tranh giữ job.

---

## 4. Mô hình dữ liệu

### 4.1. Collection `jobs` (`src/queue/job.entity.ts`)

| Trường | Ghi chú |
|---|---|
| `id` | ULID 26 ký tự, sinh trong app, **unique + index**, sắp xếp theo thời gian |
| `type` | `'order.created'` |
| `status` | `pending \| running \| completed \| failed` |
| `payload` | Object payload (**chỉ chứa mã đơn + eventId**, không chứa payload webhook) |
| `attempts` / `maxAttempts` | 0/3 → tăng 1 mỗi lần `claim` |
| `lockedBy` / `lockedAt` / `lockToken` | Worker đang giữ job; `lockToken` là `randomUUID()` |
| `heartbeatAt` | Lần gia hạn gần nhất |
| `availableAt` | Chỉ nhận job khi `availableAt <= now` (dùng cho backoff) |
| `processedRows` / `totalRows` | Tiến độ (hiện chưa được ghi nhiều) |
| `error` | Lỗi, cắt còn 2000 ký tự |
| `resultKey` | Khóa kết quả (chưa dùng) |
| `startedAt` / `finishedAt` / `createdAt` / `updatedAt` | Mốc thời gian |

Index (`job.entity.ts:103-112`):

```
{ status: 1, createdAt: 1 }      → nhận job cũ trước (FIFO)
{ status: 1, availableAt: 1 }    → nhận job đã đến hạn thử lại
{ lockedBy: 1, heartbeatAt: 1 }  → tra cứu job đang giữ
{ type: 1, createdAt: -1 }       → bộ điều khiển / lọc theo loại
```

### 4.2. Collection `webhook_events` (`src/webhook-private/webhook-private.entity.ts`)

Lưu **payload webhook đầy đủ** để worker đọc lại và để replay.

Trạng thái: `received → queued → processing → processed`
ngoài ra: `ignored` (topic không quan tâm), `invalid` (payload lỗi), `failed` (xử lý lỗi).
Các trường: `orgId`, `topic`, `haravanOrderId`, `payload`, `headers`, `hmacVerified`,
`haravanRetryCount`, `jobId`, `error`, `processedAt`.

> **Thiết kế:** job chỉ tham chiếu `webhookEventId`, payload nằm riêng ⇒ bảng `jobs` không phình to.

---

## 5. Luồng vào (3 điểm khởi tạo job)

### 5.1. Webhook riêng tư — `POST /api/v1/webhooks/haravan`
`src/webhook-private/webhook-private.controller.ts`

1. **Guard** `WebhookPrivateHmacGuard` (`webhook-private.guard.ts`)
   - Yêu cầu header `X-Haravan-Hmacsha256` + `rawBody` (đã bật `rawBody: true` ở `main.ts:16`).
   - Secret lấy theo `orgId` từ `HARAVAN_ORG_SECRETS`, fallback `HARAVAN_WEBHOOK_SECRET`.
   - Ký sai → **401** và ghi log `flow=hmac_rejected`.
2. Đọc meta (`readWebhookMeta`) → `topic`, `orgId`, `orderId`, `isTest`.
3. `extractOrder(headers, body)` để lấy `orgId` + `order.id`; lỗi thì `error`.
4. Payload test (`X-Haravan-Test`) → `error = 'payload test …'`.
5. **`webhookService.record(...)`** — lưu payload, trạng thái `RECEIVED` (hoặc `INVALID` nếu có `error`).
6. Nếu `error` ≠ null hoặc thiếu `orgId`/`orderId` → trả `200 {status:'invalid_payload'}` (**không tạo job**).
7. Nếu `topic` ∉ `{orders/create, orders/update, orders/paid}` → `markStatus(IGNORED)`, trả `200 {status:'ignored'}` (**không tạo job**).
8. **`jobQueue.enqueue('order.created', { orgId, haravanOrderId, webhookEventId, topic })`**
9. `markStatus(eventId, QUEUED, { jobId })`
10. Trả `200 {received:true, eventId, status:'queued'}`.

> Mục đích: trả lời Haravan trong thời hạn webhook (Haravan thử lại tối đa **19 lần / 48h**,
> thất bại liên tiếp có thể **xóa đăng ký** — trích chú trong code dòng 49-50).

### 5.2. Webhook ứng dụng — `POST /api/v1/webhooks/app`
`src/webhook-app/webhook-app.controller.ts:120`

- Guard `WebhookAppHmacGuard` — secret lấy từ collection `app_installations` (`resolveClientSecret`), fallback `HARAVAN_APP_ORG_SECRETS` / `HARAVAN_APP_CLIENT_SECRET`.
- Nhận body dạng order trực tiếp, `{ data }` hoặc `{ data: { order } }`.
- Thiếu `orgId` hoặc `order.id` → trả `200` với `queued: undefined` (không job), ghi log `bo_qua_thieu_du_lieu`.
- Ngược lại: `record()` (status `QUEUED`) → `enqueue(..., { source: 'webhook-app' })` → `markStatus(QUEUED, {jobId})`.
- **Bọc `try/catch` quanh việc tạo job**: nếu `enqueue` thất bại (ví dụ chưa có handler) vẫn **trả 200** với `queued: false` để Haravan không gửi lại.

**Bước đăng ký (GET):** `GET /webhooks/app?hub.verify_token&hub.challenge`
→ `verifySubscriptionToken` (theo org, fallback env) → `beginSubscription` (`PENDING`) →
`confirmSubscription` (`ACTIVE`) → trả về nguyên `hub.challenge` dạng `text/plain`.

### 5.3. Replay thủ công — `POST /api/v1/orders/webhooks/:eventId/replay`
`src/order/order.controller.ts:397`
→ tìm event → `extractOrder({}, event.payload)` → `enqueue('order.created', …)`.
Dùng để chạy lại webhook đã lỗi/lưu trữ.

### Hàm `enqueue` (`mongo-job-queue.service.ts:107`)

```ts
if (!this.handlers.has(name)) throw new Error(`Khong co handler cho job "${name}"`);
// → create { id: ulid(), type, status:'pending', attempts:0,
//            maxAttempts:3, availableAt: now }
```

`ulid()` được cài thủ công (`mongo-job-queue.service.ts:38`): 10 ký tự thời gian +
16 ký tự ngẫu nhiên Crockford Base32, tăng dần trong cùng 1ms để không trùng.

---

## 6. Machine trạng thái của Job

```
                      enqueue()
                          │
                          ▼
                    ┌──────────┐  claim (atomic findOneAndUpdate, $inc attempts)
                    │ pending  │ ────────────────────────────────┐
                    └────┬─────┘                                 ▼
        availableAt      │                              ┌──────────────┐
        chưa đến hạn ────┘ (không được claim)           │   running    │
                                                        └───┬──────┬───┘
                       handler OK                           │      │ handler throw
                       complete()                           │      │ fail()
                             │                              │      │
                             ▼                              │      ├─ attempts < maxAttempts
                    ┌──────────────┐                        │      │   → pending (availableAt = now + backoff)
                    │  completed   │                        │      └─ attempts = maxAttempts
                    └──────────────┘                        │          → failed
                                                            │
                        heartbeat quá hạn leaseMs (90s) ◄───┘
                        reclaimExpired(): $inc attempts -1
                        → pending (availableAt = now)
```

**Không tồn tại trạng thái `retry`** — job chờ thử lại vẫn là `pending` với `availableAt` lùi/lùi tương lai (`job.entity.ts:6-9`).

---

## 7. Vòng lặp Worker — chi tiết

`src/queue/job.worker.ts`

### 7.1. Khởi động — `onApplicationBootstrap()` (dòng 50)
- Nếu `JOB_QUEUE_ENABLED=false` → log cảnh báo và **không chạy gì**.
- `setInterval(pump, pollIntervalMs=1000)`.
- `reclaim()` ngay 1 lần + `setInterval(reclaim, reclaimIntervalMs=300000)`.
- `pump()` lần đầu ngay lập tức (không cần chờ chu kỳ).

### 7.2. `pump()` — nhận việc (dòng 80)
```ts
if (this.pumping || this.stopping) return;      // chống chạy lồng nhau
while (!this.stopping && this.running.size < concurrency) {   // 5 job
  const job = await this.jobQueue.claim();
  if (!job) break;                               // hàng đợi rỗng
  this.execute(job);                             // không await → chạy song song
}
```
Guard `pumping` đảm bảo chỉ có một luồng `pump` tại một thời điểm.

### 7.3. `claim()` — nhận việc nguyên tử (`mongo-job-queue.service.ts:162`)
```ts
findOneAndUpdate(
  { status:'pending', availableAt: { $lte: now } },
  { $set: { status:'running', lockedBy, lockedAt, heartbeatAt, startedAt, lockToken },
    $inc: { attempts: 1 } },
  { sort: { createdAt: 1 }, new: true }
)
```
- MongoDB bảo đảm **chỉ một worker nhận được** mỗi job khi nhiều tiến trình tranh chấp.
- Ưu tiên job tạo trước (FIFO).
- `$inc attempts: 1` ⇒ lần chạy đầu tiên `attempt = 1`.
- Trả về `null` nếu không có job đến hạn.

### 7.4. `execute(job)` — xử lý (dòng 98)
1. Thiếu `lockToken` → log lỗi và **bỏ job** (không xử lý).
2. Bật **heartbeat**: `setInterval(() => queue.heartbeat(id, lockToken), 4000ms)`
   — chạy **song song** với handler, nếu không job chạy lâu sẽ bị thu hồi và chạy trùng ở worker khác.
3. Đăng ký vào `this.running` (Map jobId → slot).
4. Chạy bất đồng bộ:
   - `await this.jobQueue.dispatch(job)` → gọi handler đã đăng ký.
   - Thành công → `complete(id, lockToken)` → `status=completed`, `$unset` toàn bộ khóa, xóa `error`.
   - Thất bại → `fail(id, lockToken, message)`.
5. `finally`: dừng heartbeat, xóa khỏi `running`, **`pump()` lại** để lấp đầy chỗ trống.

### 7.5. `fail()` — thử lại có giãn cách (`mongo-job-queue.service.ts:265`)
```ts
willRetry = attempts < maxAttempts
delay     = min(backoffBaseMs * 2^(attempts-1), backoffMaxMs)
status    = willRetry ? 'pending' : 'failed'
availableAt = now + delay          // kể cả khi failed cũng set (không ảnh hưởng vì status khác pending)
error     = message.slice(0, 2000)
$unset: lockedBy, lockedAt, heartbeatAt, lockToken
```

**Bảng backoff (mặc định base=1000ms, max=30000ms, maxAttempts=3):**

| Lần claim | `attempts` sau claim | Nếu fail | Chờ trước lần sau |
|---|---|---|---|
| 1 | 1 | còn lượt → `pending` | `1000 × 2⁰` = **1s** |
| 2 | 2 | còn lượt → `pending` | `1000 × 2¹` = **2s** |
| 3 | 3 | hết lượt → **`failed`** | — |

Tổng tối đa 3 lần thử, thời gian chờ tối đa 30s/lần (nếu tăng `maxAttempts` lên thì các lần sau kẹp ở 30s).

### 7.6. `reclaimExpired()` — thu hồi job bỏ dở (`mongo-job-queue.service.ts:327`)
```ts
deadline = now - leaseMs (90s)
find({ status:'running', heartbeatAt: { $lt: deadline } }).limit(100)
// với từng job: updateOne với điều kiện trùng hash để tránh tranh chấp
→ status='pending', availableAt=now, $inc attempts: -1,
  error='Lease het han (worker khong con nhip tim), tra ve pending'
```
- `$inc: -1` ⇒ **không tính lần thử** khi worker chết đột ngột (không làm hết lượt thử oan).
- Điều kiện `heartbeatAt` khớp giá trị đã đọc ⇒ an toàn nếu worker sống lại và vừa gia hạn.
- Mỗi job vẫn giữ `error` mô tả nguyên nhân để chẩn đoán.

### 7.7. Dừng — `onModuleDestroy()` (dòng 159)
- `stopping = true`, clearInterval poll/reclaim.
- **Dừng heartbeat nhưng KHÔNG hủy/chuyển trạng thái job đang chạy** — để `reclaimExpired` trả về `pending` sau 90s → worker khác (hoặc tiến trình mới) xử lý tiếp.
- `MongoJobQueue.onModuleDestroy()` cũng chỉ log, không đổi trạng thái (`mongo-job-queue.service.ts:406`).

---

## 8. Handler xử lý — `OrderWorker`

`src/order/order.worker.ts`

**Đăng ký:** `onModuleInit()` → `jobQueue.registerHandler('order.created', job => handleOrderCreated(job))` (dòng 28).

> Vì `enqueue()` bắt buộc phải có handler, thứ tự khởi tạo module rất quan trọng:
> `OrderModule` (nơi có `OrderWorker`) import `QueueModule`.

### 8.1. `handleOrderCreated(job)` — dòng 35

```
payload = { orgId, haravanOrderId, webhookEventId?, topic }
   │
   ├─ 1. (nếu có webhookEventId) markStatus(PROCESSING, { jobId })
   │
   ├─ 2. loadPayload(webhookEventId, orgId, haravanOrderId)
   │       ├─ webhookService.extractOrderPayload(...)  ← đọc payload đã lưu
   │       │     • kiểm tra event.orgId/haravanOrderId khớp
   │       │     • extractOrder(headers_lưu, payload) và so order.id === haravanOrderId
   │       └─ fallback: orderService.fetchOrderFromApi(orgId, id)  ← gọi Haravan API
   │
   ├─ 3. orderService.processIncomingOrder({ orgId, payload, source:'webhook', jobId, topic })
   │
   ├─ 4. Nếu khách có danh tính thật (hasRealCustomerIdentity)
   │        → countPriorOrders() để lấy số đơn/chi tiêu trước đó (bọc try/catch, lỗi chỉ warn)
   │
   ├─ 5. markStatus(PROCESSED)
   │
   ├─ 6. logOrderDecision(...) → file logs/order-decision.log
   │
   └─ LỖI: logOrderDecision(error) + markStatus(FAILED, {error, jobId}) + throw
            → fail() ở worker → retry/backoff
```

**`loadPayload` (dòng 163):** ưu tiên payload webhook đã xác thực; nếu không có →
log warn và gọi `fetchOrderFromApi` (Haravan API `getOrder`).

### 8.2. Business rule — `OrderService.processIncomingOrder` (`order.service.ts:536`)

```
upsertOrder(orgId, payload, source, topic)      // ghi/merge đơn hàng
upsertCustomer(orgId, payload, topic)           // ghi/merge khách hàng
order.status = PROCESSING; save
   │
evaluateConfirmEligibility(orgId, order)        // (order.service.ts:462)
   │   skip nếu:
   │     • không có danh tính khách thật        → NO_CUSTOMER
   │     • cancelled / closed                   → ORDER_CANCELLED
   │     • confirmed_status = 'confirmed'       → ALREADY_CONFIRMED
   │     • priorOrderCount < minPriorOrders(1)  → FIRST_TIME_BUYER / NOT_ENOUGH_PRIOR_ORDERS
   │     • priorSpent < minPriorSpent (nếu >0)  → NOT_ENOUGH_PRIOR_SPENT
   │   pass nếu đủ → shouldConfirm = true
   │
logAction(EVALUATE)
   │
   ├─ shouldConfirm = false → order.status = SKIPPED (hoặc CANCELLED)
   │                          ghi processing{reason, prior…} → return
   └─ shouldConfirm = true  → confirmOrder({ manual:false, actor:'system', source })
```

### 8.3. `confirmOrder` (`order.service.ts:608`)

```
tìm đơn (không có → 404)
evaluateConfirmEligibility lại (force=true thì bỏ qua rule)
   ├─ không đủ điều kiện → status=SKIPPED + logAction(CONFIRM_FAILED/SKIPPED) → return
   └─ đủ điều kiện → logAction(CONFIRM_SEND)
          → apiClient.confirmOrder(orgId, orderId)
               POST /orders/{id}/confirm.json  body { confirmed_status:'confirmed' }
          Thành công → status=CONFIRMED + logAction(CONFIRM_SUCCESS, kèm apiCall)
          Lỗi       → status=FAILED + logAction(CONFIRM_FAILED) + throw
```

`throw` ở đây lan lên `OrderWorker` → `fail()` → job retry.
Lưu ý: **lỗi API nội bộ đã retry sẵn trong `api.service.ts`** (xem §9).

### 8.4. `countPriorOrders` (`order.service.ts:415`)

Đếm đơn trước đó của cùng khách trong cùng `orgId`:
- Điều kiện danh tính: `haravanId` **hoặc** `phone` **hoặc** `email`.
- `$or: [{customer.haravanId}, {phone chuẩn hoá}, {email}]`,
  loại `status != cancelled`, loại chính đơn hiện tại.
- Trả `{ priorOrderCount, priorSpent }` (tổng `totalPrice`).

---

## 9. Lớp retry HTTP bên trong `ApiService`

`src/api/service.api.ts` — `request()` (dòng 231):

```
for attempt = 1..maxRetries (3)
  ├─ res ok            → return
  ├─ !res.retryable || hết lượt → throw
  └─ network error     → retry nếu còn lượt
  sleep(retryBaseDelayMs * 2^(attempt-1))   // 500ms, 1000ms, 2000ms
```

⇒ **2 tầng retry:**
- **Nội bộ HTTP:** tối đa 3 lần, backoff 500ms→2s (chỉ cho lỗi được coi là `retryable`).
- **Job queue:** tối đa 3 lần, backoff 1s→2s (cho mọi lỗi handler ném ra).

Tổng số lần gọi API có thể đạt `3 × 3 = 9` cho một job trong trường hợp xấu nhất.

---

## 10. Trạng thái của `webhook_events` theo thời gian

| Thời điểm | Trạng thái | Nơi set |
|---|---|---|
| Guard xác thực HMAC thành công | `received` | `webhook-private.controller.ts:125` |
| Payload lỗi / payload test / thiếu orgId+orderId | `invalid` | `webhook-private.controller.ts:123` |
| Topic không thuộc 3 topic xử lý | `received` → `ignored` | `webhook-private.controller.ts:149` |
| Đã tạo job | `queued` (+`jobId`) | `webhook-private.controller.ts:175` |
| Worker bắt đầu xử lý | `processing` (+`jobId`) | `order.worker.ts:47` |
| Xử lý thành công | `processed` (+`processedAt`) | `order.worker.ts:98` |
| Xử lý lỗi | `failed` (+`error`, `jobId`) | `order.worker.ts:147` |

> Webhook ứng dụng ghi thẳng `QUEUED` ngay lúc `record()` (`webhook-app.controller.ts:177`).

**Quan sát:** bảng `webhook_events` là nguồn sự thật để xem một sự kiện đã đi tới đâu.

---

## 11. Chuỗi thời gian (sequence) của một webhook hợp lệ

```
T+0ms     Haravan POST /api/v1/webhooks/haravan
T+~1ms    HmacGuard: verify base64(HMAC_SHA256(rawBody, secret))   ✅
T+~2ms    readWebhookMeta + extractOrder
T+~5ms    webhook_events.create  { status: received, payload: ... }
T+~6ms    jobs.create            { id: ULID, status: pending, availableAt: now }
T+~7ms    webhook_events.update  { status: queued, jobId }
T+~8ms    HTTP 200 { received, eventId, status: 'queued' }   ◀── Haravan nhận phản hồi

   ... (tối đa pollIntervalMs = 1000ms sau)

T+~1000ms JobWorker.pump() → claim()   [atomic]  attempts=1, status=running
T+~1001ms heartbeat timer bắt đầu (mỗi 4000ms)
T+~1001ms OrderWorker: markStatus(processing)
T+~1002ms đọc payload từ webhook_events  (hoặc fallback gọi API)
T+~1010ms upsertOrder + upsertCustomer
T+~1020ms evaluateConfirmEligibility → countPriorOrders (2 query)
T+~1030ms [nếu đủ điều kiện] confirmOrder → POST Haravan API (retry ≤3)
T+~???ms  status=CONFIRMED / SKIPPED / FAILED
T+        markStatus(processed)  +  log order-decision.log
T+        complete() → jobs.status = completed
```

---

## 12. Quan sát, log và bảo trì

### 12.1. Endpoint

| Endpoint | Ý nghĩa |
|---|---|
| `GET /api/v1/orders/queue` | Thống kê queue (aggregate trực tiếp từ MongoDB) |

`getStats()` (`mongo-job-queue.service.ts:379`) trả:
```json
{ "driver":"mongodb", "pending":n, "running":n, "processed":n, "failed":n, "retried":n }
```
- `pending/running/processed/failed` → đếm `aggregate $group by status` (chính xác sau restart).
- `retried` → **bộ đếm trong bộ nhớ**, reset về 0 khi khởi động lại tiến trình.

### 12.2. File log

| File | Nội dung |
|---|---|
| `logs/webhook.log` | Mỗi request webhook 1 dòng JSON (`logWebhookPayload`), gồm `stage: received/processed`, `flow`, headers, raw body (cắt 20KB) |
| `logs/order-decision.log` | Kết quả quyết định mỗi đơn: khách cũ/mới, số đơn trước, chi tiêu trước, `confirmed`, `skipReason` (`order-decision-logger.ts`) |
| Logger NestJS (stdout) | `MongoJobQueue`, `JobWorker`, `OrderWorker`, controller… |

### 12.3. Dọn dẹp

`purgeCompleted(olderThanDays = 7)` (`mongo-job-queue.service.ts:415`) xoá
`completed`/`failed` có `finishedAt` > 7 ngày.
⚠️ **Hiện không được gọi từ bất kỳ đâu** trong mã nguồn → collection `jobs` sẽ phình theo thời gian nếu không có cron/scheduler bên ngoài.

---

## 13. Các tình huống đặc biệt & cách hệ thống ứng phó

| Tình huống | Hành vi |
|---|---|
| HMAC sai / thiếu header / thiếu rawBody | Guard ném **401**, ghi `hmac_rejected` vào `logs/webhook.log`, Haravan sẽ thử lại |
| Thiếu secret cấu hình cho org | 401 `Webhook chua duoc cau hinh` |
| Payload test `X-Haravan-Test` | Lưu `invalid`, không tạo job, vẫn 200 |
| Topic lạ (không phải orders/*) | Lưu `ignored`, không tạo job, vẫn 200 |
| Payload thiếu orgId/orderId | Vẫn **200** để Haravan ngừng gửi lại |
| `enqueue` thất bại (app webhook) | Bắt lỗi, trả 200 với `queued:false`, ghi log `loi_khi_tao_job` |
| Payload webhook không còn (bị xoá) | `loadPayload` fallback gọi `GET /orders/{id}.json` của Haravan API |
| Worker chết khi đang xử lý | Không có heartbeat > 90s → `reclaimExpired` đưa về `pending`, `$inc attempts:-1`, job chạy lại ở lần poll kế tiếp (≤5 phút một lần quét) |
| Handler chạy quá 90s mà heartbeat vẫn OK | Vẫn giữ job (heartbeat gia hạn mỗi 4s) |
| Handler ném lỗi | `fail()` → retry với backoff 1s/2s → lần 3 fail → `failed` + `error` lưu 2000 ký tự |
| Ứng dụng restart | Không đổi trạng thái job; job `running` sẽ được reclaim khi hết lease |
| Nhiều tiến trình / replica | `findOneAndUpdate` nguyên tử + `lockToken` ⇒ không trùng lặp xử lý |
| `JOB_QUEUE_ENABLED=false` | Worker không khởi động; job vẫn được enqueue nhưng không ai xử lý |
| Replay | `POST /api/v1/orders/webhooks/:eventId/replay` tạo job mới từ payload đã lưu |

---

## 14. Nhận xét / điểm cần lưu ý khi vận hành

1. **Job có thể xử lý 2 lần** nếu handler chạy đúng ~90s mà hệ thống phân mảnh mạng khiến
   heartbeat không tới nơi: job bị reclaim về `pending` và chạy song song. Code chấp nhận
   rủi ro này (at-least-once) — `upsertOrder` idempotent nên dữ liệu không hỏng, nhưng
   `confirmOrder` có thể gọi API thừa (đã có guard `ALREADY_CONFIRMED` chặn lần sau).
2. **`purgeCompleted()` chưa được lên lịch** → nên thêm scheduler (cron) hoặc gọi khi boot.
3. **`retried` trong `getStats()` là counter bộ nhớ** → không dùng làm số liệu giám sát dài hạn.
4. **Chỉ 1 loại job có handler** (`order.created`); `order.confirm` / `order.sync_customer`
   mới chỉ là khai báo hằng — nếu gọi `enqueue` sẽ ném `Khong co handler cho job ...`.
5. **Không có dead-letter queue**: job `failed` chỉ nằm trong collection `jobs` với `error`;
   phải dùng replay thủ công để chạy lại.
6. **Không có watchdog cảnh báo** khi số `pending` tăng đột biến — chỉ có `GET /orders/queue`.
7. **Log ghi đồng bộ** (`appendFileSync`) trong request path → có thể tắc luồng khi log lớn.

---

## 15. Tóm tắt một dòng

> **Webhook (HMAC ✓) → lưu `webhook_events` → tạo `jobs` (pending) → trả 200 →
> `JobWorker` poll 1s, claim nguyên tử (≤5 job/ tiến trình), heartbeat 4s,
> handler `OrderWorker` đọc lại payload → tính rule khách hàng cũ/mới →
> gọi `POST /orders/{id}/confirm.json` → `complete`/`fail` (retry 3 lần, backoff 1s→2s) →
> job mất heartbeat 90s được reclaim về `pending`.**
