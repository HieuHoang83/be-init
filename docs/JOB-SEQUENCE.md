# Job System - Luồng chi tiết (Step by Step)

| Bước | Actor | Hành động | Kết quả |
|---|---|---|---|
| 1 | User | Bấm "Cập nhật ngược lên Haravan" | Trigger handle |
| 2 | FE | Check `isLocked()` | Nếu `pending/processing` → disable form. Chuông vẫn enable. |
| 3 | FE | `POST /api/products/:code/haravan-reverse-sync` | Gọi API |
| 4 | BE | Check job active `(userId,productCode)` `status in {pending,processing}` | Có → `202` (idempotency, **KHÔNG tạo mới**). Không → tạo `pending` + push queue (jobId cố định, attempts=5, exp backoff 2000ms) → `202` |
| 5 | FE | Nhận `202` | **1 toast.loading** (`Infinity`, `closeButton:false`). Set `activeJob` (có `toastId`). `isLocked()=true` → form lock. |
| 6 | BullMQ | Phân phối job | Giao worker |
| 7 | Worker | **Atomic claim** `pending→processing` (`UPDATE ... WHERE id=? AND status='pending' RETURNING *`) | Claim OK → set `startedAt`, sync `attempts = job.attemptsMade`. Không → check existing (completed/error/processing) → return. |
| 8 | Worker | `reverseSyncToHaravan()` | Thực thi sync |
| 9a | Worker | **Success** | `completed`, lưu `result`, clear errors. Tạo notification `haravan_reverse_sync_success`. Publish `user:{userId}:jobs` status `completed`. Return. |
| 9b | Worker | **Fail (throw)** | `errMsg`, `isFinal = attemptsMade>=maxAttempts`. **!isFinal:** CHỈ update `lastError/errorMessage` → **throw** (retry ẩn). **isFinal:** `status='error'`, tạo notification `haravan_reverse_sync_error`, publish terminal có `error_message` → **KHÔNG throw**. |
| 10 | FE (SSE) | Nhận `job:update` terminal (`completed\|error`) | Filter `job_id===activeJob.jobId`. Update status. **Update inplace** toast cùng `toastId` (`duration:5000, closeButton:true`). Sau ~5.5s `clearActiveJob()` (guard jobId) → unlock. |
| 11 | FE (Poll) | Poll `/api/jobs/:id` 1.5s khi running | Terminal → xử lý như 10, stop interval. Running → sync status. |

**Ghi nhớ:** Retry trung gian **không** tạo toast lỗi/notification. Unlock **chỉ** khi nhận terminal + clear activeJob (~5.5s). Chuông **luôn enable** khi locked. **1 toast duy nhất** (loading→update inplace).
