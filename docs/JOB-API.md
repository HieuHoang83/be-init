# Job System - API & Contracts

## 1. Tạo Job (Idempotency)

**Endpoint:** `POST /api/products/:code/haravan-reverse-sync`

**Auth:** Required

1. Kiểm tra job active `(userId, productCode)` với `status IN ('pending','processing')` (DESC `createdAt`, LIMIT 1).
2. **Nếu có job active:** Trả `202 Accepted` (idempotency, **KHÔNG** tạo mới)

```json
{
  "job_id": "...",
  "status": "pending|processing",
  "product_code": "...",
  "type": "haravan_reverse_sync",
  "message": "Đang có tiến trình cập nhật ngược lên Haravan cho sản phẩm này."
}
```

3. **Nếu không có job active:** Tạo `jobs` (`status='pending'`, `attempts=0`, `maxAttempts=5`, `type='haravan_reverse_sync'`). Add queue BullMQ:

```ts
{
  jobId: uuid,
  attempts: 5,
  backoff: { type: 'exponential', delay: 2000 },
  removeOnComplete: { count: 100 },
  removeOnFail: { count: 100 }
}
```

Trả `202 Accepted`:

```json
{
  "job_id": "...",
  "status": "pending",
  "product_code": "...",
  "type": "haravan_reverse_sync"
}
```

## 2. Lấy Job (Fallback Poll)

**Endpoint:** `GET /api/jobs/:id`

**Auth:** Required (chỉ owner)

**Response:** `200 OK`

```json
{
  "job": {
    "id": "...",
    "status": "pending|processing|completed|error",
    "type": "haravan_reverse_sync",
    "productCode": "...",
    "attempts": 0,
    "maxAttempts": 5,
    "lastError": null,
    "errorMessage": null,
    "result": null,
    "payload": {},
    "createdAt": "...",
    "startedAt": "...",
    "completedAt": "...",
    "failedAt": "...",
    "updatedAt": "..."
  }
}
```

**404** nếu không tồn tại hoặc không thuộc user.

## 3. SSE Realtime

**Endpoint:** `GET /api/events`

**Auth:** Required

- `Content-Type: text/event-stream`, keep-alive, heartbeat `: ping` mỗi 15s
- Event: `job:update`
- Data:

```json
{
  "job_id": "uuid",
  "type": "haravan_reverse_sync",
  "product_code": "...",
  "status": "completed|error",
  "error_message": "..." // chỉ khi status === 'error'
}
```
