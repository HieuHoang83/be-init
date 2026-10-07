# Job System - Realtime (SSE + Poll Fallback)

## 1. Redis Pub/Sub

- **Channel:** `user:{userId}:jobs`
- **Publisher:** Worker (khi terminal: `completed` hoặc `error` final)
- **Subscriber:** SSE `GET /api/events`
- **Lưu ý:** `redisPub` và `redisSub` là **2 connection riêng biệt** (Node Redis v4 Pub/Sub).

## 2. SSE (Primary)

**Endpoint:** `GET /api/events` (Auth)

- `text/event-stream`, keep-alive, heartbeat `: ping` 15s
- Event: `job:update`

**FE (useJobEvents):**
- Chỉ xử lý khi `evt.job_id === activeJob.jobId` và `status in {completed,error}` (terminal)
- Update status → **update inplace** toast cùng `toastId` (`duration:5000, closeButton:true`)
- Sau **~5.5s** `clearActiveJob()` (guard jobId) → unlock form
- Non-terminal (`pending/processing`) → sync status nếu cần

## 3. Poll Fallback

**Endpoint:** `GET /api/jobs/:id` (Auth), **interval 1.5s**

- Chỉ poll khi `pending/processing`, stop khi terminal
- Terminal: update inplace toast cùng `toastId`, stop interval, sau **~5.5s** `clearActiveJob()` (guard jobId) → unlock form
- Bỏ qua lỗi poll
