

# Luồng hoạt động Job + Worker (BE)

## 1. Tổng quan

Phần BE được xây dựng theo mô hình **Job Queue + Worker** (BullMQ + Redis + Postgres). Mục tiêu chính:

- API tạo job trả về ngay (`202 Accepted`), tách biệt request và xử lý nền.
- Xử lý **retry ẩn với user**: chỉ khi worker đã thực hiện **đủ toàn bộ số lần thử (`max_attempts`)** mà vẫn thất bại mới coi là `error` (final failure) và mới tạo notification.
- Chỉ có `completed` và `error` là trạng thái **terminal**. Các trạng thái `pending/processing` là đang chạy.
- Đảm bảo **idempotency** khi tạo job, tránh race condition khi claim job.

## 2. Kiến trúc

Client (FE)
  ↓  POST /products/:code/haravan-reverse-sync
API (Express)
  → Tạo jobs (pending)
  → Push vào BullMQ Queue (Redis)
  ↓
BullMQ Queue (haravan_reverse_sync)
  → Phân phối job cho Worker (theo concurrency)
  ↓
Worker (BullMQ)
  → Claim: pending → processing
  → Gọi service reverseSyncToHaravan()
      → Thành công → completed + tạo notification + publish event
      → Thất bại  → nếu chưa final: chỉ ghi last_error + throw (retry)
                   → nếu final: error + tạo notification + publish event
Redis Pub/Sub (user:{user_id}:jobs)
  → SSE (/api/events) → FE
Postgres (jobs, notifications) – Source of truth

## 3. Database

### 3.1 Bảng `jobs`

Lưu toàn bộ trạng thái, số lần thử, lỗi và kết quả của job.

| Column | Type | Mô tả |
|---|---|---|
| `id` | UUID (PK) | ID duy nhất của job |
| `user_id` | UUID | User sở hữu job |
| `type` | VARCHAR(50) | `haravan_reverse_sync` |
| `product_code` | VARCHAR(50) | Mã sản phẩm cần đồng bộ ngược lên Haravan |
| `payload` | JSONB | Dữ liệu gửi kèm khi tạo job |
| `status` | VARCHAR(20) | Trạng thái: `pending`, `processing`, `completed`, `error` |
| `attempts` | INT | Số lần thử đã thực hiện (được đồng bộ với BullMQ) |
| `max_attempts` | INT | Số lần thử tối đa (mặc định `5`) |
| `last_error` | TEXT | Lỗi gần nhất (ghi ở các attempt chưa final) |
| `error_message` | TEXT | Thông báo lỗi cuối cùng (chỉ khi `error` – final failure) |
| `result` | JSONB | Kết quả trả về khi `completed` |
| `started_at` | TIMESTAMPTZ | Thời điểm worker bắt đầu xử lý (`processing`) |
| `completed_at` | TIMESTAMPTZ | Thời điểm job hoàn thành (`completed`) |
| `failed_at` | TIMESTAMPTZ | Thời điểm job thất bại cuối cùng (`error`) |
| `created_at` | TIMESTAMPTZ | Thời điểm tạo job |
| `updated_at` | TIMESTAMPTZ | Thời điểm cập nhật gần nhất |

**Indexes:**
- `idx_jobs_user_status (user_id, status)` – lọc job active theo user
- `idx_jobs_product_user (product_code, user_id, created_at DESC)` – kiểm tra job active theo sản phẩm

### 3.2 Bảng `notifications`

Lưu inbox thông báo cho user (source of truth).

| Column | Type | Mô tả |
|---|---|---|
| `id` | UUID (PK) | ID thông báo |
| `user_id` | UUID | User nhận thông báo |
| `job_id` | UUID (FK → jobs.id, SET NULL) | Liên kết với job (nếu có) |
| `type` | VARCHAR(50) | `haravan_reverse_sync_success` hoặc `haravan_reverse_sync_error` |
| `title` | VARCHAR(255) | Tiêu đề thông báo |
| `content` | TEXT | Nội dung thông báo |
| `payload` | JSONB | Thông tin bổ sung (product_code, job_id, result/error) |
| `read_at` | TIMESTAMPTZ | Null nếu chưa đọc, có giá trị nếu đã đọc |
| `created_at` | TIMESTAMPTZ | Thời điểm tạo thông báo |

**Indexes:**
- `idx_notifications_user_unread (user_id, read_at)` – danh sách chưa đọc
- `idx_notifications_job (job_id)` – tra cứu theo job

## 4. API Endpoints (BE)

### 4.1 `POST /products/:code/haravan-reverse-sync`
Tạo job cập nhật ngược lên Haravan.

**Logic xử lý:**

1. Lấy `userId` từ auth middleware.
2. **Kiểm tra job active (Idempotency):**
   ```ts
   jobs.findFirst({
     where: {
       user_id: userId,
       product_code: code,
       status: { in: ['pending', 'processing'] }
     },
     orderBy: { created_at: 'desc' }
   })
- Nếu tồn tại → trả 202 Accepted với { job_id, status, message: 'Đang có tiến trình...' } (không tạo job mới).
3. Tạo job mới:
- Tạo record jobs với status='pending', attempts=0, max_attempts=5, payload = req.body ?? {}.
4. Đẩy vào Queue:
- haravanReverseSyncQueue.add('sync', { jobId: job.id }, { jobId: job.id.toString(), attempts: 5, backoff: { type: 'exponential', delay: 2000 } })
5. Trả 202 Accepted với { job_id, status: 'pending' }.
4.2 GET /jobs/:id
Lấy thông tin chi tiết của job (dựa vào user).
- Query: jobs.findFirst({ where: { id, user_id } })
- Trả 200 nếu tồn tại, 404 nếu không hoặc không thuộc user.
4.3 GET /notifications
Lấy danh sách thông báo của user.
- Query params: unread=1, limit, offset
- Filter: read_at IS NULL nếu unread==='1'
- Trả { items, totalUnread }
4.4 PATCH /notifications/:id/read
Đánh dấu 1 thông báo đã đọc.
- Update read_at = NOW() với điều kiện id, user_id
- Trả notification đã cập nhật
4.5 PATCH /notifications/read-all
Đánh dấu tất cả thông báo chưa đọc thành đã đọc.
- updateMany({ user_id, read_at: null }, { read_at: NOW() })
- Trả { success: true }
4.6 GET /api/events (SSE)
Realtime stream theo user-scoped.
- Auth required, trả Content-Type: text/event-stream
- Subscribe Redis channel user:{user_id}:jobs
- Mỗi khi worker publish event → push data: {json}\n\n đến client
- Cleanup khi client đóng kết nối (unsubscribe + quit Redis sub)
5. Queue (BullMQ)
5.1 Cấu hình Queue
export const haravanReverseSyncQueue = new Queue('haravan_reverse_sync', {
  connection: redis,
  defaultJobOptions: {
    removeOnComplete: { count: 100 },
    removeOnFail: { count: 1000 },
    attempts: 5,
    backoff: { type: 'exponential', delay: 2000 },
  },
});
- attempts: 5 – số lần thử tối đa (phải đồng bộ với max_attempts trong DB)
- backoff: exponential, delay: 2000 – retry sau 2s, 4s, 8s,... (ẩn với user)
- removeOnComplete/Fail – dọn job cũ trong Redis
5.2 Tên Job
Sử dụng tên sync khi add job: queue.add('sync', { jobId })
6. Worker (BullMQ) – Luồng xử lý chi tiết
Worker chạy với concurrency: 5, xử lý nhiều job song song.
Bước W1. Nhận Job
Worker nhận Job<{ jobId: string }> từ queue.
Bước W2. Claim Job (pending → processing)
const claimed = await db.jobs.updateMany({
  where: { id: jobId, status: 'pending' },
  data: { status: 'processing', started_at: new Date() },
});
if (claimed.count === 0) return; // Đã claimed hoặc terminal
Chỉ claim khi status === 'pending' để tránh race condition.
Bước W3. Load Job + Đồng bộ Attempts
1. Lấy current = await db.jobs.findUnique({ where: { id: jobId } })
2. Lấy attemptsMadeByBull = job.attemptsMade ?? 0
3. Tính attemptsToStore = attemptsMadeByBull + 1
4. Cập nhật attempts = attemptsToStore trong DB (nếu chưa khớp)
Dùng job.attemptsMade của BullMQ để đảm bảo số lần thử chính xác (tính cả attempt hiện tại).
Bước W4. Thực thi Service
Gọi await reverseSyncToHaravan({ productCode, payload, userId })
Bước W5. Trường hợp THÀNH CÔNG (completed)
1. Update job → completed
await db.jobs.update({
  where: { id: jobId },
  data: {
    status: 'completed',
    completed_at: new Date(),
    result,
    last_error: null,
    error_message: null,
  },
});
2. Tạo notification success
await db.notifications.create({
  data: {
    user_id: current.user_id,
    job_id: current.id,
    type: 'haravan_reverse_sync_success',
    title: 'Cập nhật ngược lên Haravan thành công',
    content: `Đã cập nhật ngược lên Haravan thành công: ${current.product_code}`,
    payload: { product_code: current.product_code, job_id: current.id, result },
  },
});
3. Publish event terminal (completed)
await pub.publish(
  `user:${current.user_id}:jobs`,
  JSON.stringify({
    job_id: current.id,
    type: current.type,
    product_code: current.product_code,
    status: 'completed',
  })
);
4. return result (job hoàn thành thành công)
Bước W6. Trường hợp THẤT BẠI (Error) – Retry ẩn + Final Failure
1. Lấy errMsg = err?.message ? String(err.message) : 'Unknown error'
2. Tính toán isFinal:
const attemptsMade = job.attemptsMade ?? 0;
const maxAttempts = job.opts?.attempts ?? current.max_attempts;
const isFinal = attemptsMade >= maxAttempts;
W6.1 Chưa phải lần thử cuối cùng (isFinal === false)
- Chỉ ghi last_error, KHÔNG đổi status thành error, KHÔNG tạo notification.
await db.jobs.update({
  where: { id: jobId },
  data: { last_error: errMsg },
});
- throw err → BullMQ tự động retry job theo backoff: exponential, delay: 2000 (retry hoàn toàn ẩn với user). Job có thể quay lại logic xử lý ở các attempt tiếp theo.
W6.2 Lần thử cuối cùng (isFinal === true) – Final Failure
- Update job → error (terminal)
await db.jobs.update({
  where: { id: jobId },
  data: {
    status: 'error',
    failed_at: new Date(),
    last_error: errMsg,
    error_message: errMsg,
    result: null,
  },
});
- Tạo notification error
await db.notifications.create({
  data: {
    user_id: current.user_id,
    job_id: current.id,
    type: 'haravan_reverse_sync_error',
    title: 'Cập nhật ngược lên Haravan thất bại',
    content: `Cập nhật ngược lên Haravan thất bại: ${current.product_code}. Vui lòng thử lại sau.`,
    payload: { product_code: current.product_code, job_id: current.id, error: errMsg },
  },
});
- Publish event terminal (error)
await pub.publish(
  `user:${current.user_id}:jobs`,
  JSON.stringify({
    job_id: current.id,
    type: current.type,
    product_code: current.product_code,
    status: 'error',
    error_message: errMsg,
  })
);
- Không throw thêm sau khi đã xác định final failure (tránh log retry thừa).
7. Realtime (Redis Pub/Sub + SSE)
7.1 Publish Event
Worker publish JSON string lên channel user:{user_id}:jobs khi đạt trạng thái terminal (completed hoặc error). Với processing/pending không publish event bắt buộc (FE có fallback poll).
Event payload:
{
  "job_id": "uuid",
  "type": "haravan_reverse_sync",
  "product_code": "YOU3333",
  "status": "completed"
}
hoặc
{
  "job_id": "uuid",
  "type": "haravan_reverse_sync",
  "product_code": "YOU3333",
  "status": "error",
  "error_message": "..."
}
7.2 Subscribe qua SSE
Route GET /api/events tạo Redis subscriber riêng theo connection, lắng nghe channel user:{user_id}:jobs, forward message dạng data: <msg>\n\n. Khi request close/error → cleanup subscriber.
8. Luồng Retry – Giải thích rõ ràng
Attempt	attemptsMade (BullMQ)	isFinal (>= maxAttempts=5)	Hành động Worker	Notification
Attempt 1 (lần thử 1) – fail	0	0 >= 5 = false	Update last_error + throw err → BullMQ retry	Không tạo
Attempt 2 – fail	1	false	Update last_error + throw err	Không tạo
Attempt 3 – fail	2	false	Update last_error + throw err	Không tạo
Attempt 4 – fail	3	false	Update last_error + throw err	Không tạo
Attempt 5 (lần thử cuối cùng) – fail	4	4 >= 5? → true (BullMQ đếm attemptsMade tăng dần. Với attempts:5, attempt cuối là khi attemptsMade >= 5 theo cấu hình)	Set status='error', lưu error_message, tạo notification + publish event	Tạo notification error
Nguyên tắc cốt lõi: Tất cả các lần thất bại trước attempt cuối cùng đều được xử lý nội bộ (retry ẩn). Chỉ duy nhất khi attempt cuối cùng vẫn thất bại mới chuyển job sang error (terminal) và mới bắn notification lỗi cho user.
9. Các nguyên tắc quan trọng (BE)
Nguyên tắc	Giải thích
Claim chỉ khi pending	Sử dụng updateMany với where: { status: 'pending' } để tránh việc xử lý lại job đã được claim hoặc đã ở trạng thái terminal.
Idempotency tạo job	Kiểm tra (user_id, product_code) có job pending/processing → nếu có trả về job active, không tạo mới.
Retry hoàn toàn ẩn	Ở attempt chưa final: không set status='error', không tạo notification. Chỉ last_error + throw err. User không thấy bất kỳ thông báo lỗi nào trong lúc retry.
Chỉ notify khi terminal	Notification success chỉ tạo khi completed. Notification error chỉ tạo khi error (final failure).
Terminal = 2 trạng thái	Chỉ completed và error là terminal. FE dùng điều kiện này để unlock UI (bắt buộc, không dựa vào toast auto-close).
User-scoped Pub/Sub	Event chỉ phát trên kênh user:{user_id}:jobs, đảm bảo isolation giữa users.
Attempts đồng bộ	Đồng bộ jobs.attempts với job.attemptsMade của BullMQ để đảm bảo tính nhất quán dữ liệu.
```	 