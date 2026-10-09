# Thao tác đơn hàng đi qua hàng đợi

Mọi thao tác đẩy lên Haravan từ người dùng đều chạy qua job queue. Controller
không gọi Haravan trực tiếp nữa.

## Luồng

1. FE gọi API (ví dụ `POST /api/v1/orders/:orgId/:haravanOrderId/confirm`).
2. Controller đẩy công việc vào hàng đợi và trả `202 Accepted`:

```json
{ "queued": true, "jobId": "01J...", "action": "confirm", "status": "pending" }
```

3. Worker (`OrderActionWorker`) nhận việc, gọi Haravan, đồng bộ lại bản ghi đơn
   hàng và ghi kết quả vào `resultKey` của job.
4. FE poll `GET /api/v1/orders/:orgId/jobs/:jobId` mỗi 2 giây tới khi job
   `completed` hoặc `failed`, rồi báo toast và tải lại danh sách/chi tiết đơn.

## Danh sách job

| Job | Nguồn | Ghi chú |
| --- | --- | --- |
| `order.created` | webhook | `OrderWorker`, có retry theo `HARAVAN_QUEUE_MAX_ATTEMPTS` |
| `order.create` | `POST :orgId/create` | `maxAttempts: 1` để không sinh đơn nhép khi thử lại |
| `order.confirm` | `POST :orgId/:haravanOrderId/confirm` | |
| `order.cancel` | `POST :orgId/:haravanOrderId/cancel` | |
| `order.close` | `POST :orgId/:haravanOrderId/close` | |
| `order.open` | `POST :orgId/:haravanOrderId/open` | |
| `order.update` | `PUT :orgId/:haravanOrderId` | |
| `order.refund` | `POST :orgId/:haravanOrderId/refunds` | |
| `order.transaction` | `POST :orgId/:haravanOrderId/transactions` | |

## Hình dạng job trả về

```json
{
  "id": "01J...",
  "name": "order.confirm",
  "status": "pending|running|completed|failed",
  "attempts": 1,
  "maxAttempts": 3,
  "error": null,
  "result": "{\"message\":\"Đã xác nhận đơn #123\",\"haravanOrderId\":123,\"confirmed\":true}"
}
```

`result` là JSON do worker ghi; FE parse bằng `parseJobResult` để lấy message và
`haravanOrderId` (dùng cho `order.create`).

## Chống chết hàng đợi khi Haravan chậm

- Số request gửi song song lên Haravan = `HARAVAN_QUEUE_CONCURRENCY` (mặc định 5).
- Job lỗi được thử lại với backoff luỹ thừa `HARAVAN_QUEUE_BACKOFF_BASE_MS` →
  `HARAVAN_QUEUE_BACKOFF_MAX_MS` tối đa `HARAVAN_QUEUE_MAX_ATTEMPTS` lần.
- Worker chết giữa chừng được đưa về hàng đợi nhờ `reclaimExpired`.
