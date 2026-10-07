# Job System - So sánh với Webhook/App

> **Chức năng:** Giải thích cách tư duy webhook/app được áp dụng vào luồng Job (API trả 202 ngay, retry ẩn, chỉ thông báo khi terminal).

## 1. Tư duy Webhook/App

Trong mô hình webhook/app điển hình:

- **Fire-and-forget:** API nhận request → đẩy vào queue/background job → **trả 202 Accepted ngay** (không chờ xử lý xong).
- **Retry ẩn (hidden retries):** Khi xử lý tạm thời lỗi (timeout, 5xx...) hệ thống tự retry ngầm với backoff. Người dùng **không** thấy lỗi ở các lần retry trung gian.
- **Final failure:** Chỉ báo lỗi khi **đã hết toàn bộ lần retry** (thất bại cuối cùng).
- **Terminal-only notifications:** Side-effect (thông báo, callback) chỉ xảy ra khi job đạt trạng thái **kết thúc** (`completed` hoặc `error` final).
- **Idempotency:** Tránh double processing bằng key nghiệp vụ (vd: `eventId`, `requestId`) hoặc job active.

## 2. Áp dụng vào Job System

| Điểm Webhook/App | Job System (Haravan Reverse Sync) | Giải thích |
|---|---|---|
| **API trả 202 ngay** | `POST /api/products/:code/haravan-reverse-sync` → `202 Accepted` | API chỉ tạo job + enqueue, **KHÔNG** `await` worker. |
| **Fire-and-forget** | Tạo job `pending` → push BullMQ → trả 202 ngay | Tránh timeout request, đúng chuẩn webhook. |
| **Idempotency** | Kiểm tra job `pending/processing` theo `(userId, productCode)` → nếu có trả lại job active (202), **KHÔNG** tạo mới | Tránh double submit khi user bấm nhiều lần. |
| **Hidden retries** | BullMQ `exponential backoff` (delay 2000ms, attempts 5). Attempt trung gian (`attemptsMade < maxAttempts`) → **CHỈ** update `lastError/errorMessage`, **KHÔNG** set `error`, **KHÔNG** tạo notification, **KHÔNG** publish terminal → **throw error** để retry | User **hoàn toàn không thấy** lỗi trong lúc retry. Đúng "retry ẩn với user". |
| **Final failure** | `attemptsMade >= maxAttempts` → set `status='error'` (terminal), tạo `notifications` (`haravan_reverse_sync_error`), publish terminal có `error_message`, **KHÔNG throw** | Chỉ thông báo khi **thất bại sau khi đã retry đủ toàn bộ lần thử**. |
| **Terminal-only** | Chỉ publish event `job:update` khi `status==='completed'` hoặc `status==='error'` (final). Không publish ở attempt trung gian | FE chỉ cập nhật toast/unlock khi job **kết thúc thật sự**. |
| **Callback/out-of-band** | Redis Pub/Sub → SSE (`job:update`) + Poll fallback (`/api/jobs/:id` 1.5s) | FE nhận kết quả **ngoài luồng request** (out-of-band), giống webhook callback + polling backup. |
| **Stateful tracking** | Lưu `jobs` + `notifications` trong DB (source of truth). FE có `activeJob` + guard `jobId` | Dễ trace, retry, audit. Notification Center lưu lịch sử (khác với toast tạm thời). |

## 3. Key Point

> **"API ack ngay (202) → Xử lý ngầm + retry ẩn → Chỉ thông báo khi job đạt trạng thái terminal"**

Đó là tư duy **webhook/app** được áp dụng đầy đủ trong Job System này.
