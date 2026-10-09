# Haravan Sync — Backend (NestJS)

Hệ thống đồng bộ và vận hành đơn hàng Haravan: nhận webhook, lưu đơn vào MongoDB,
tự động xác nhận đơn theo luật nghiệp vụ, và cung cấp API cho frontend quản trị
đơn hàng / khách hàng / kho.

Frontend tương ứng: [`../fe-QLDA`](../fe-QLDA) (Next.js 14 App Router).

---

## 1. Công nghệ

| Thành phần | Công nghệ |
|---|---|
| Framework | NestJS 10 |
| Database | MongoDB + Mongoose 8 |
| Hàng đợi | Mongo collection tự viết (`queue/`), không phụ thuộc BullMQ/Redis |
| Xác thực | JWT (access + refresh) + Passport |
| Validate | class-validator qua global `ValidationPipe` |
| Tài liệu API | Swagger |
| Test | Jest + ts-jest (mongodb-memory-server) |

## 2. Chạy local

```bash
# 1. Cài dependency
npm install

# 2. Tạo file môi trường
cp .env.example .env

# 3. Điền MongoDB + secret webhook + token Haravan trong .env

# 4. Chạy ở chế độ watch
npm run start:dev
```

API chạy ở `http://localhost:3000/api`.

| Lệnh | Tác dụng |
|---|---|
| `npm run build` | Build ra `dist/` |
| `npm run start:prod` | Chạy bản build (`node dist/src/main.js`) |
| `npm test` | Chạy toàn bộ unit test |
| `npm run lint` | ESLint + fix |
| `npm run format` | Prettier |
| `npm run seed:admin` | Tạo tài khoản admin đầu tiên |

## 3. Biến môi trường

Xem `.env.example` để có bản đầy đủ. Các nhóm chính:

- **MongoDB** — `MONGODB_URI`, `MONGODB_DB_NAME`.
- **Webhook riêng tư** — `HARAVAN_WEBHOOK_SECRET`, hoặc map nhiều shop qua
  `HARAVAN_ORG_SECRETS={"123456":"secret-a"}`.
- **Webhook ứng dụng** — `HARAVAN_APP_VERIFY_TOKEN`, `HARAVAN_APP_CLIENT_SECRET`,
  `HARAVAN_APP_ORG_SECRETS`.
- **Gọi Omni API** — `HARAVAN_API_BASE_URL`, `HARAVAN_API_TIMEOUT_MS`,
  `HARAVAN_API_MAX_RETRIES`, `HARAVAN_API_RETRY_DELAY_MS`.
- **Luật auto-confirm** — `HARAVAN_MIN_PRIOR_ORDERS`, `HARAVAN_MIN_PRIOR_SPENT`.
- **Hàng đợi** — `HARAVAN_QUEUE_CONCURRENCY`, `HARAVAN_QUEUE_MAX_ATTEMPTS`,
  `JOB_QUEUE_POLL_INTERVAL_MS`, `JOB_QUEUE_LEASE_MS`.
- **JWT** — `JWT_ACCESS_TOKEN_SECRET`, `JWT_REFRESH_TOKEN_SECRET` và hạn sử dụng.

Toàn bộ cấu hình được khai báo và kiểm tra kiểu trong một chỗ: [`src/config.ts`](src/config.ts).

## 4. Kiến trúc

Tổ chức theo **feature module** — mỗi nghiệp vụ một thư mục dưới `src/`:

```
src/
  auth/            JWT, guard, strategy, đăng nhập/đăng ký
  user/            hồ sơ người dùng
  customer/        lưu khách hàng đồng bộ từ webhook đơn hàng
  order/           đơn hàng: entity, DTO, service, worker xử lý webhook
  queue/           hàng đợi Mongo + worker nền (claim, lease, retry)
  webhook-private/ webhook ký HMAC (shop tự cấu hình)
  webhook-app/     webhook ứng dụng (OAuth + verify token)
  api/             HTTP client gọi Haravan Omni API (token, retry, timeout) + HaravanGateway (lớp nền)
  haravan-product/     controller + service + spec: sản phẩm và biến thể
  haravan-customer/    controller + service + spec: khách hàng và địa chỉ
  haravan-location/    controller + service + spec: kho
  haravan-inventory/   controller + service + spec: tồn kho, phiếu mua/nhập, chuyển kho
  haravan-collection/  controller + service + spec: bộ sưu tập
  haravan-collect/     controller + service + spec: collect (sản phẩm trong bộ sưu tập)
  haravan-geo/         controller + service + spec: tỉnh / huyện / xã
  discount/        chiết khấu và khuyến mãi
  shop-settings/   cấu hình theo shop
  core/            util dùng chung (payload webhook, interceptor, guard)
  config.ts        cấu hình ứng dụng (registerAs)
```

### Luồng xử lý đơn hàng

```
Haravan webhook
   │  (HMAC / verify token)
   ▼
WebhookController ──► OrderService.upsertOrder()      lưu đơn + snapshot khách
   │
   ▼
JobQueue.enqueue()  ──► trả 202 ngay cho Haravan
   │
   ▼
OrderWorker (nền) ──► đánh giá luật ──► confirmOrder() qua Omni API
   │
   ├──► order_actions : nhật ký kỹ thuật (mỗi lần gọi API, kết quả, thời gian)
   └──► order_events  : sự kiện nghiệp vụ (đã hủy, đã hoàn tiền...)
```

Hai bảng log tách biệt có chủ đích:

- `order_actions` — log **kỹ thuật**: mỗi lần gọi API, retry, lỗi (dùng để debug).
- `order_events` — log **nghiệp vụ**: những gì con người quan tâm (dùng cho timeline UI).

### Gọi Haravan API

Mọi lời gọi Omni API đi qua một chuỗi rõ ràng:

```
Controller → HaravanXxxService → HaravanGateway.forward() → ApiClient → Haravan
```

- `ApiClient` lo phần giao thức: lấy access token theo shop, retry lũy thừa khi gặp
  429 / 5xx / lỗi mạng, timeout theo cấu hình, và chuẩn hoá lỗi thành `ApiError` để
  tầng trên phân biệt lỗi retry được hay không.
- `HaravanGateway` (`src/api/haravan.gateway.ts`) là lớp nền chung, chỉ có hàm `forward()`.
- Mỗi module `haravan-*` có **service riêng** kế thừa lớp nền đó và chỉ chứa các
  endpoint thuộc đúng tài nguyên của nó.

```ts
// Controller chỉ phụ thuộc vào service của đúng domain
constructor(private readonly haravan: HaravanInventoryService) {}
```


Trước đây một lớp `HaravanOmniService` chứa toàn bộ ~80 endpoint và mọi service của
từng domain đều `extends` từ nó — nên service sản phẩm cũng có method của kho. Nay mỗi
service chỉ có method của đúng domain của nó.

## 5. API chính

| Prefix | Mô tả |
|---|---|
| `/api/orders` | Danh sách, chi tiết, xác nhận, hủy, đóng/mở, cập nhật, hoàn tiền, giao dịch |
| `/api/customers` | Khách hàng đồng bộ và thống kê |
| `/api/haravan/:orgId/*` | Proxy CRUD sản phẩm, biến thể, kho, khách, địa chỉ, địa lý, chiết khấu |
| `/api/webhooks/...` | Nạp webhook (riêng tư và ứng dụng), phát lại webhook lỗi |
| `/api/shops/:orgId/settings` | Cấu hình shop |
| `/api/auth/*` | Đăng nhập, đăng ký, refresh token |

Danh sách route đầy đủ được in ra khi chạy `npx jest src/modules.di.spec.ts`.

## 6. Test

```bash
npm test                 # toàn bộ
npx jest src/order       # theo module
```

Hiện có 10 suite / 118 test, bao phủ: luật auto-confirm, webhook payload và HMAC,
retry của HTTP client, filter danh sách đơn, mapping endpoint của từng gateway,
DI của toàn hệ thống.

## 7. Script vận hành

Các script bảo trì nằm trong [`scripts/`](scripts):

| Script | Tác dụng |
|---|---|
| `seed-admin.ts` | Tạo tài khoản admin |
| `haravan-token.mjs` | Đổi authorization code lấy access token |
| `check-webhook-secret.mjs` | Đối chiếu secret webhook |
| `test-webhook-app.mjs` | Gửi webhook ứng dụng giả lập |
| `migrate-customer-indexes.mjs` | Tạo index cho collection khách hàng |
| `cleanup-garbage-orders.mjs` | Dọn đơn rác |
| `audit-orders.mjs` | Thống kê trạng thái đơn trong DB |

## 8. Tài liệu

Xem [`docs/README.md`](docs/README.md) để biết tài liệu nào còn dùng.
