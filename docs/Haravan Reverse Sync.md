
# Luồng hoạt động hệ thống - Haravan Reverse Sync

## 1. Mục tiêu

Hệ thống cập nhật ngược lên Haravan được thiết kế theo cơ chế **Job + Queue + Worker** (tham khảo webhook/app), nhằm đảm bảo:

- API trả về ngay (`202 Accepted`) mà không chờ worker xử lý xong (tránh timeout).
- Chỉ bắn thông báo khi job đã **kết thúc hoàn toàn**. Với lỗi, phải **retry đủ toàn bộ lần thử mới coi là thất bại cuối cùng** (retry hoàn toàn ẩn với user).
- Toast trạng thái "đang xử lý" được giữ **persistent** (không tự động ẩn). Chỉ tự động ẩn khi job đạt trạng thái **terminal** (`completed` hoặc `error`), với thời gian **5s**.
- UI bị khoá dựa hoàn toàn theo **job status** (`pending/processing`), chỉ được unlock khi nhận trạng thái **terminal**.
- Notification Center (icon chuông) là **source of truth** lưu lịch sử thông báo, toast chỉ là feedback tạm thời tại thời điểm kết thúc.

## 2. Các thành phần hệ thống

| Thành phần | Vai trò |
|---|---|
| **FE (React + Zustand)** | Gọi API tạo job, quản lý active job, hiển thị toast (loading/success/error), lock/unlock form, lắng nghe realtime (SSE), hiển thị Notification Center. |
| **API (Express)** | Tạo job, kiểm tra job active (tránh trùng), đẩy job vào Queue, trả `202 { job_id, status }`. |
| **BullMQ Queue (Redis)** | Quản lý hàng đợi job, điều phối worker, xử lý retry với `exponential backoff`, theo dõi `attemptsMade`. |
| **Worker (BullMQ)** | Claim job, chuyển trạng thái `pending → processing`, thực thi cập nhật ngược lên Haravan, xử lý retry ẩn với user, cập nhật trạng thái terminal, tạo notification, phát event realtime. |
| **Postgres (DB)** | Lưu `jobs` (trạng thái, attempts, max_attempts, last_error, error_message, result, timestamps) và `notifications` (inbox của user). |
| **Redis Pub/Sub** | Phát event theo kênh `user:{user_id}:jobs` để FE nhận realtime. |
| **SSE (`/api/events`)** | Stream event realtime đến FE theo user-scoped. |
| **Notification Center (Chuông)** | Hiển thị danh sách thông báo, badge unread, đánh dấu đã đọc từng cái hoặc tất cả. |

## 3. Trạng thái Job

| Status | Ý nghĩa |
|---|---|
| `pending` | Job đã được tạo và đẩy vào queue, đang chờ Worker claim để xử lý. |
| `processing` | Worker đã claim job thành công, đang thực thi quá trình cập nhật ngược lên Haravan. |
| `completed` | Xử lý thành công. **Trạng thái terminal**. |
| `error` | Thất bại **sau khi đã retry đủ toàn bộ lần thử (final failure)**. **Trạng thái terminal**. |

> Chỉ `completed` và `error` là trạng thái terminal. `pending`/`processing` là trạng thái đang chạy.

## 4. Luồng hoạt động chi tiết

### Bước 1. User bấm "Cập nhật ngược lên Haravan"
- User thao tác trên `ProductForm`.
- FE dựa vào `useJobStore.isLocked()` để kiểm tra: nếu `active.status` là `pending` hoặc `processing` → nút "Cập nhật" bị `disabled`, toàn bộ vùng form bị lock.

### Bước 2. Gọi API tạo Job
1. FE gọi `POST /products/:code/haravan-reverse-sync`
2. BE kiểm tra **job active** cho `(user_id, product_code)` với điều kiện `status IN ('pending','processing')` (sắp xếp theo `created_at DESC`).
   - **Nếu có job active**: trả `202 { job_id, status, message: 'Đang có tiến trình cập nhật ngược lên Haravan cho sản phẩm này.' }` (đảm bảo idempotency, tránh tạo job trùng).
   - **Nếu không có job active**: tạo record `jobs` với `status='pending'`, `attempts=0`, `max_attempts=5`, `payload` từ body request → đẩy job vào `haravanReverseSyncQueue` (BullMQ) với `jobId`, `attempts=5`, `backoff: { type: 'exponential', delay: 2000 }` → trả `202 { job_id, status:'pending' }`.

### Bước 3. FE hiển thị Toast + Lock UI
1. Nhận response `202` → FE tạo `toast.loading()` với nội dung:
   `Đang cập nhật ngược lên Haravan: {productCode}...`
   - `duration: Infinity` (không tự động ẩn)
   - `closeButton: false` (không cho user đóng thủ công khi đang chạy)
2. Lưu `activeJob = { jobId, productCode, status: 'pending', toastId }` vào Zustand store.
3. `isLocked()` trả về `true` → toàn bộ input/select/button bị `disabled`. **Icon chuông (Notification Bell) vẫn hoạt động bình thường**.

> **Quan trọng:** Lock UI chỉ dựa vào `job.status` (`pending/processing`). **KHÔNG** dựa vào việc toast tự ẩn để unlock UI.

### Bước 4. Worker claim Job (pending → processing)
1. BullMQ phân phối job đến Worker.
2. Worker thực hiện `updateMany` với điều kiện `status = 'pending'` → cập nhật `status = 'processing'`, `started_at = NOW()`. (Chỉ claim khi `pending` để tránh race condition).
3. Lấy lại job hiện tại (`jobs`). Đồng bộ `attempts` với `job.attemptsMade` của BullMQ: `attemptsToStore = attemptsMadeByBull + 1` để đảm bảo số lần thử chính xác.
4. Job chuyển sang `processing`. FE có thể nhận trạng thái này qua Realtime/Poll nhưng **toast vẫn là loading persistent**.

### Bước 5. Thực thi cập nhật ngược lên Haravan
Worker gọi `reverseSyncToHaravan({ productCode, payload, userId })` để thực hiện đồng bộ lên Haravan.

- **Nếu thành công** → Bước 6.
- **Nếu thất bại (throw Error)** → Bước 7.

### Bước 6. Thành công (completed)
1. Cập nhật `jobs`: `status = 'completed'`, `completed_at = NOW()`, lưu `result`, clear `last_error`, `error_message`.
2. Tạo record trong `notifications` với `type = 'haravan_reverse_sync_success'`:
   - `title`: `Cập nhật ngược lên Haravan thành công`
   - `content`: `Đã cập nhật ngược lên Haravan thành công: {product_code}`
   - `payload`: `{ product_code, job_id, result }`
3. **Publish event terminal** lên Redis Pub/Sub kênh `user:{user_id}:jobs`:
   ```json
   {
     "job_id": "...",
     "type": "haravan_reverse_sync",
     "product_code": "YOU3333",
     "status": "completed"
   }
4. Worker trả kết quả (job completed).
Bước 7. Thất bại + Retry ẩn với User
Khi reverseSyncToHaravan throw Error:
1. Lấy errMsg = error.message || 'Unknown error'.
2. Tính attemptsMade = job.attemptsMade (BullMQ), maxAttempts = job.opts?.attempts ?? 5.
3. isFinal = attemptsMade >= maxAttempts.
4. Nếu isFinal === false (chưa phải lần thử cuối cùng):
- Chỉ cập nhật jobs.last_error = errMsg (KHÔNG set status = 'error', KHÔNG tạo notification)
- throw err để BullMQ thực hiện retry với exponential backoff (retry hoàn toàn ẩn với user)
5. Nếu isFinal === true (đã retry đủ toàn bộ lần thử):
- Cập nhật jobs: status = 'error', failed_at = NOW(), last_error = errMsg, error_message = errMsg, result = null
- Tạo notifications với type = 'haravan_reverse_sync_error':
- title: Cập nhật ngược lên Haravan thất bại
- content: Cập nhật ngược lên Haravan thất bại: {product_code}. Vui lòng thử lại sau.
- Publish event terminal lên kênh user:{user_id}:jobs:
{
  "job_id": "...",
  "type": "haravan_reverse_sync",
  "product_code": "YOU3333",
  "status": "error",
  "error_message": "..."
}
Bước 8. FE nhận event terminal (Realtime + Fallback)
1. SSE: FE subscribe /api/events, lắng nghe job:update (data event). Khi nhận event có job_id === activeJob.jobId và status là completed hoặc error → gọi handleTerminal().
2. Fallback Poll: Khi active.status là pending/processing, FE poll GET /jobs/:id mỗi 1.5s. Nếu trả về completed|error → xử lý terminal, nếu vẫn pending/processing → chỉ update status (toast vẫn persistent).
3. Xử lý terminal trên FE:
- updateStatus(status) trong store
- Update toast duy nhất (cùng toastId) từ loading → success hoặc error, set duration: 5000, closeButton: true
- Sau ~5.5s gọi clear() active job → unlock form (dựa theo job status). UI chỉ unlock khi nhận terminal, không dựa vào auto-close của toast.
5. Nguyên tắc quan trọng
Nguyên tắc	Giải thích
Idempotency	Chặn tạo job trùng khi đã tồn tại job pending hoặc processing cho cùng (user_id, product_code). Trả lại job active với 202.
Chỉ claim khi pending	Dùng updateMany({ status: 'pending' }) để tránh race condition khi job được re-enqueue.
Retry ẩn với user	Notification chỉ được tạo khi là final failure (error sau đủ lần thử). Tất cả attempt trung gian chỉ ghi last_error và throw err. User không thấy toast lỗi lúc retry.
1 toast duy nhất	Dùng cùng toastId (loading → success/error) để tránh spam toast.
Persistent loading	Khi pending/processing: toast.loading với duration: Infinity, closeButton: false.
Auto-close 5s khi terminal	Khi completed/error: cập nhật toast inplace với duration: 5000, closeButton: true.
Unlock dựa theo job status	Form chỉ được unlock khi job đạt trạng thái terminal (`completed
Source of truth	Thông báo được lưu trong bảng notifications. Toast chỉ là feedback ngắn hạn tại thời điểm kết thúc, user có thể xem lại trong Notification Center bất kỳ lúc nào.
User-scoped events	Event realtime phát theo kênh user:{user_id}:jobs để đảm bảo chỉ user đúng mới nhận được event của job mình.