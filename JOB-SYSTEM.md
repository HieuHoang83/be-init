# Job System - Haravan Reverse Sync (Tóm tắt)

> **Mục đích:** Tổng quan ngắn gọn về luồng Job (tạo job → queue → worker → terminal → báo FE). Xem chi tiết trong `docs/`.

Hệ thống dùng **Job + Queue + Worker** (BullMQ + Redis + Postgres).

- **API 202 ngay:** trả về mà không chờ worker.
- **Retry ẩn:** chỉ báo lỗi khi **thất bại sau đủ lần retry** (attempt trung gian chỉ ghi `lastError`).
- **1 toast duy nhất:** `toast.loading` (Infinity, close:false) → update inplace `success/error` (5s, close:true).
- **Unlock chỉ dựa terminal:** form unlock sau ~5.5s khi nhận `completed|error` (SSE hoặc poll). **Chuông luôn hoạt động** khi form locked.
- **Idempotency:** tránh tạo job trùng `(userId, productCode)` khi có `pending/processing`.
- **Realtime + fallback:** SSE `job:update` + poll `/api/jobs/:id` mỗi 1.5s.
- **Source of truth:** Notifications DB. Toast chỉ feedback tạm thời.

**Chi tiết:** xem `docs/JOB-OVERVIEW.md`, `docs/JOB-API.md`, `docs/JOB-WORKER-QUEUE.md`, `docs/JOB-WEBHOOK.md`, `docs/JOB-REALTIME.md`, `docs/JOB-FRONTEND.md`, `docs/JOB-SEQUENCE.md`.
