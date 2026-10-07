# Job System - Queue & Worker

## 1. BullMQ Queue

**Queue:** `haravan-reverse-sync`

```ts
{
  attempts: 5,
  backoff: { type: 'exponential', delay: 2000 },
  removeOnComplete: { count: 100 },
  removeOnFail: { count: 100 }
}
```

- Dùng `jobId` cố định khi `add()` (map 1-1 với DB `jobs.id`).
- Dựa `job.attemptsMade` (BullMQ) để xác định `isFinal`.

## 2. Worker

### 2.1 Atomic Claim (`pending → processing`)

```sql
UPDATE jobs
SET status='processing', started_at=NOW(), updated_at=NOW()
WHERE id=? AND status='pending'
RETURNING *
```

- Claim thành công → xử lý.
- Không claim được → check existing: `completed`→return result, `error`→return null, `processing`→return null.

### 2.2 Sync Attempts

Sau claim: `attempts = job.attemptsMade` (BullMQ).

### 2.3 Thành công (`completed`)

1. Update `jobs` → `status='completed'`, `completed_at=NOW()`, `result`, clear `lastError/errorMessage`.
2. Tạo `notifications` type `haravan_reverse_sync_success`.
3. Publish `user:{userId}:jobs`:

```json
{
  "job_id": "...",
  "type": "haravan_reverse_sync",
  "product_code": "...",
  "status": "completed"
}
```

### 2.4 Thất bại + Retry ẩn

```ts
const errMsg = error.message || 'Unknown error';
const isFinal = attemptsMade >= maxAttempts;
```

**Attempt trung gian (`!isFinal`):**
- Chỉ update `lastError, errorMessage, updated_at`
- **KHÔNG** set `status='error'`, **KHÔNG** tạo notification, **KHÔNG** publish terminal
- **throw error** → BullMQ retry (ẩn hoàn toàn với user)

**Final failure (`isFinal`):**
- Update `jobs` → `status='error'`, `failed_at=NOW()`, `lastError/errMsg`, `result=null`
- Tạo `notifications` type `haravan_reverse_sync_error`
- Publish terminal có `error_message`
- **KHÔNG throw** (return `null`)
