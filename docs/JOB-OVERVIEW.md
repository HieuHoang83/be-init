# Job System - Tổng quan

> **Chức năng:** Giới thiệu kiến trúc, thành phần, trạng thái Job và mục tiêu tổng thể của hệ thống Haravan Reverse Sync.

## 1. Mục tiêu

Hệ thống cập nhật ngược lên Haravan sử dụng mô hình **Job + Queue + Worker**.

- API trả về ngay `202 Accepted` (không chờ worker).
- **Retry hoàn toàn ẩn với người dùng**: chỉ báo lỗi khi job thất bại **sau khi đã retry đủ toàn bộ lần thử** (các attempt trung gian chỉ ghi `lastError`).
- Toast "đang xử lý" được giữ **persistent** (`duration: Infinity`, `closeButton: false`). Chỉ cập nhật thành `success`/`error` khi job đạt trạng thái **terminal**.
- Form/UI chỉ được **unlock** khi nhận trạng thái **terminal** (`completed` | `error`). Không unlock dựa vào việc toast tự đóng.
- **Notification Center** là source of truth. Toast chỉ là feedback tạm thời tại thời điểm kết thúc.
- **Idempotency**: tránh tạo job trùng theo `(user_id, product_code)` khi đã có job `pending` hoặc `processing`.

## 2. Các thành phần

| Thành phần | Vai trò |
|---|---|
| **FE (React + Zustand + Sonner)** | Gọi API, quản lý `activeJob`, **1 toast duy nhất** (loading → success/error), lock/unlock form, SSE + poll fallback. |
| **API (Express)** | Tạo job, check active, đẩy queue, trả `202`. |
| **BullMQ + Redis** | Queue, điều phối worker, retry `exponential backoff`, theo dõi `attemptsMade`. |
| **Worker (BullMQ)** | Claim (`pending → processing`), xử lý sync, retry ẩn, cập nhật terminal, tạo notification, publish event. |
| **Postgres (DB)** | Lưu `jobs`, `notifications`. |
| **Redis Pub/Sub** | Publish kênh `user:{userId}:jobs`. |
| **SSE (`GET /api/events`)** | Event `job:update` user-scoped. |
| **Notification Center (Chuông)** | Lịch sử thông báo. **Luôn hoạt động** khi form bị lock.

## 3. Trạng thái Job

| Status | Ý nghĩa | Terminal |
|---|---|---|
| `pending` | Chờ worker claim | Không |
| `processing` | Đang xử lý | Không |
| `completed` | Thành công | **Có** |
| `error` | Thất bại sau đủ lần retry | **Có** |

> Chỉ `completed` và `error` là trạng thái **terminal**.
