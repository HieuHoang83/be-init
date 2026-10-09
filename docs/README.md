# Tài liệu dự án

## Bắt đầu từ đâu

| Tài liệu | Dùng khi nào |
|---|---|
| [`../README.md`](../README.md) | Cài đặt, cấu hình, xem tổng quan kiến trúc và API |
| [`note.md`](note.md) | Ghi chú về hành vi thật của Haravan API (đã test qua Postman) |
| [`inventory.md`](inventory.md) | Tài liệu Inventory Adjustment của Haravan (nguồn gốc) |
| [`postman-orders.md`](postman-orders.md) | Hướng dẫn gọi API tìm và xem một đơn qua Postman |

## Tài liệu kiến trúc Job (tham chiếu)

Các tài liệu dưới đây mô tả **thiết kế ban đầu** của hệ thống Job dùng BullMQ + Redis + Zustand.
**Code hiện tại không dùng stack đó**: hàng đợi được cài lại trên MongoDB trong [`src/queue`](../src/queue)
và frontend dùng React Query. Giữ lại để tham khảo luồng xử lý, không phải tài liệu mô tả code.

- [`JOB-SYSTEM.md`](JOB-SYSTEM.md) — tóm tắt toàn bộ hệ thống Job
- [`JOB-OVERVIEW.md`](JOB-OVERVIEW.md) — thành phần và trạng thái Job
- [`JOB-SEQUENCE.md`](JOB-SEQUENCE.md) — luồng từng bước (ai làm gì, kết quả ra sao)
- [`JOB-WORKER-QUEUE.md`](JOB-WORKER-QUEUE.md) — thiết kế queue và worker
- [`JOB-API.md`](JOB-API.md) — hợp đồng API và idempotency
- [`JOB-WEBHOOK.md`](JOB-WEBHOOK.md) — so sánh cách tiêu webhook với luồng Job
- [`JOB-REALTIME.md`](JOB-REALTIME.md) — cập nhật trạng thái realtime
- [`JOB-FRONTEND.md`](JOB-FRONTEND.md) — tích hợp phía frontend

## Quy ước khi viết tài liệu

- Mô tả **code đang chạy**, không mô tả ý tưởng chưa triển khai.
- Khi tài liệu lệch với code, sửa tài liệu hoặc ghi rõ "tham chiếu" như trên.
