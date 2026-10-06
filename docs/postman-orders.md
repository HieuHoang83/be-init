# Hướng dẫn Postman: tìm và xem một order

Tài liệu này đi theo luồng: đăng nhập → lấy danh sách order → chọn một dòng → lấy chi tiết order và lịch sử thao tác.

## 1. Tạo environment

Trong Postman, tạo environment với các biến:

| Variable                 | Giá trị ví dụ                                            |
| ------------------------ | -------------------------------------------------------- |
| `baseUrl`                | `http://localhost:3000` hoặc domain đang chạy API        |
| `accessToken`            | Để trống, sẽ lấy sau khi login                           |
| `orgId`                  | Có thể để trống nếu lấy order từ danh sách toàn hệ thống |
| `page`                   | `1`                                                      |
| `limit`                  | `50`                                                     |
| `orderIndex`             | `0` (vị trí trong `data.items`, bắt đầu từ 0)            |
| `selectedOrgId`          | Để trống, Postman sẽ lấy từ order đã chọn                |
| `selectedHaravanOrderId` | Để trống, Postman sẽ lấy từ order đã chọn                |

Các API quản trị yêu cầu JWT. Gắn header sau cho các request trừ login/refresh:

```http
Authorization: Bearer {{accessToken}}
```

## 2. Đăng nhập

Tạo request `POST`:

```http
{{baseUrl}}/api/v1/auth/login
```

Body → raw → JSON:

```json
{
  "phone": "{{loginPhone}}",
  "password": "{{loginPassword}}"
}
```

`loginPhone` và `loginPassword` là thông tin tài khoản BE của bạn. Không lưu password thật trong file hoặc chia sẻ environment.

Response được bọc trong `data`; access token nằm tại `data.token.access_token`. Để tự lưu token, tab **Scripts → Post-response**:

```javascript
const body = pm.response.json();
pm.environment.set('accessToken', body.data.token.access_token);
```

Sau đó request khác sẽ dùng token qua `Authorization: Bearer {{accessToken}}`.

## 3. Lấy danh sách order

Để xem order ở tất cả org đã lưu trong BE, tạo request `GET`:

```http
{{baseUrl}}/api/v1/orders?page={{page}}&limit={{limit}}
```

Nếu muốn giới hạn vào một shop, thêm `orgId`:

```http
{{baseUrl}}/api/v1/orders?orgId={{orgId}}&page={{page}}&limit={{limit}}
```

Có thể thêm các filter tùy chọn: `email`, `orderNumber`, `status`, `financialStatus`, `confirmedStatus`. `limit` tối đa là 100. Danh sách được sắp xếp mới nhất trước.

Response chính nằm ở `data`:

```json
{
  "statusCode": 200,
  "message": "",
  "data": {
    "items": [
      {
        "orgId": 200001220496,
        "haravanOrderId": 1849587434,
        "orderName": "#10005",
        "orderNumber": "#10005",
        "priorOrderCount": 2,
        "isReturningCustomer": true
      }
    ],
    "total": 1,
    "page": 1,
    "limit": 50
  }
}
```

Các giá trị ví dụ chỉ để minh họa; response thực tế có thêm field order và có thể có nhiều `items`.

### Tự chọn một order bằng vị trí

Trong tab **Scripts → Post-response** của request danh sách, thêm script sau. Đặt `orderIndex` trong environment bằng vị trí muốn chọn, ví dụ `0` là dòng đầu tiên, `1` là dòng thứ hai:

```javascript
const result = pm.response.json().data;
const index = Number(pm.environment.get('orderIndex') || 0);
const order = result.items[index];

if (!order) {
  throw new Error(
    `Không có order ở vị trí ${index}; total=${result.items.length}`,
  );
}

pm.environment.set('selectedOrgId', order.orgId);
pm.environment.set('selectedHaravanOrderId', order.haravanOrderId);
pm.environment.set(
  'selectedOrderName',
  order.orderName || order.orderNumber || String(order.haravanOrderId),
);
```

Sau khi gửi request danh sách, Postman lưu `selectedOrgId` và `selectedHaravanOrderId` cho request chi tiết.

## 4. Lấy chi tiết order đã chọn

Tạo request `GET`:

```http
{{baseUrl}}/api/v1/orders/{{selectedOrgId}}/{{selectedHaravanOrderId}}
```

Response có `data.order` và `data.actions`; `order` là order đã chọn, còn `actions` là các thao tác gần đây.

Nếu chỉ muốn lịch sử thao tác, dùng:

```http
{{baseUrl}}/api/v1/orders/{{selectedOrgId}}/{{selectedHaravanOrderId}}/actions
```

## 5. Lấy orgId (tùy chọn)

Nếu muốn xem org có dữ liệu khách hàng, gọi:

```http
{{baseUrl}}/api/v1/customers/stats
```

Dùng JWT như các API quản trị khác. Xem `data.byOrg` để lấy các `orgId`. Endpoint này chỉ liệt kê org đã có dữ liệu trong bảng customers; nếu muốn lấy toàn bộ order, có thể bỏ `orgId` ở bước 3 rồi dùng `orgId` trên order được chọn cho bước 4.

## 6. Làm mới access token (khi hết hạn)

Tạo request `POST`:

```http
{{baseUrl}}/api/v1/auth/refresh-token
```

Body → raw → JSON:

```json
{
  "refreshToken": "{{refreshToken}}"
}
```

Lưu `data.access_token` trong response trở lại biến `accessToken`.

## Lưu ý

- `haravanOrderId` là ID dùng trong route chi tiết, không phải `orderNumber`/`orderName` dạng `#10005`.
- Danh sách chỉ gồm order đã được lưu trong database BE.
- `priorOrderCount` là số order trước đó được hệ thống đếm; `0` nghĩa là order đầu tiên theo dữ liệu hiện có.
