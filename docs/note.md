# Ghi chú khi làm việc với Haravan API

> Ghi chú này tổng hợp từ proxy API trong `src/api/haravan-omni.service.ts`, các controller backend, client FE và tài liệu `docs/inventory.md`. Khi tài liệu Haravan và response thực tế khác nhau, ưu tiên ghi lại payload đã test Postman kèm shop, thời điểm và endpoint; không suy luận response từ tên trường.

## Quy tắc chung

- **Tách đúng tổ chức:** proxy Omni nhận `orgId` trong URL và lấy token tương ứng của shop. Không dùng nhầm `orgId` với ID khách, sản phẩm, kho hay đơn Haravan.
- **Đường dẫn:** backend thường khai báo đường dẫn bỏ `/com` và `.json`; `ApiClient` ghép với base URL. FE gọi proxy `/api/v1/haravan/{orgId}/...`, không gọi thẳng Haravan từ trình duyệt.
- **Body có wrapper:** tài nguyên ghi thường yêu cầu `{ product: {...} }`, `{ variant: {...} }`, `{ customer: {...} }`, `{ inventory: {...} }`, `{ transfer: {...} }`. Gửi object trần có thể bị Haravan từ chối hoặc bỏ qua dữ liệu.
- **Response:** backend bọc response vào envelope `statusCode/message/data`; helper `haravanRequest()` ở FE đã trả `response.data.data`. Đừng unwrap thêm lần nữa. Payload bên trong vẫn có wrapper riêng như `products`, `product`, `locations`, `inventory_locations`…
- **Phân trang:** truyền `page`, `limit` theo API; không giả định một lần GET lấy hết dữ liệu. Nhiều list mặc định 50 bản ghi; với inventory locations tài liệu ghi tối đa 250 kết quả và tối đa 50 `location_ids`/`variant_ids` mỗi request.
- **Lỗi:** 401/403 thường là token hết hạn hoặc thiếu scope; 404 sai ID/endpoint; 400 thường là body/giá trị trường không hợp lệ; 429 là rate limit. Xem message và body lỗi Haravan trước khi sửa logic.
- **Retry và thao tác ghi:** `ApiClient` tự retry khi lỗi mạng/5xx và 429. POST có thể đã được Haravan xử lý nhưng response bị mất; retry có nguy cơ tạo trùng phiếu/sản phẩm/đơn. Với thao tác ghi, kiểm tra dữ liệu Haravan trước khi bấm gửi lại; không tự thêm retry phía FE.
- **ID và kiểu dữ liệu:** ID Haravan là số; giữ nguyên ID từ response. Query trên URL là chuỗi, nhưng body nên dùng số cho ID và số lượng. Không dùng SKU thay cho `product_id` hoặc `product_variant_id`.
- **Scope:** sản phẩm/khách hàng/kho cần scope tương ứng; inventory cần `com.read_inventories`, `com.write_inventories`; quản lý app webhook cần `wh_api`. Thiếu scope có thể trông giống lỗi endpoint nhưng thực chất là 403.

## Kho và tồn kho — phần dễ gây lệch dữ liệu nhất

### Danh sách kho và tồn tại từng kho

- `GET /com/locations.json` (proxy: `GET /api/v1/haravan/{orgId}/locations`) trả `locations[]`. Lưu/đọc các trường `id`, `name`, `location_type`, `type`, `is_primary`, `is_unavailable_quantity`, `status`, địa chỉ và điện thoại.
- `GET /com/inventory_locations.json?location_ids=...&variant_ids=...` (proxy: `/inventory_locations`) trả `inventory_locations[]`. Trường quan trọng: `loc_id`, `product_id`, `variant_id`, `qty_onhand`, `qty_commited`, `qty_incoming`, `qty_available`, `updated_at`.
- `inventory_locations` là tồn theo **cặp kho + biến thể**. Luôn match cả `loc_id` và `variant_id` (và `product_id` nếu có); đừng lấy tồn toàn hệ thống hoặc chỉ match SKU.
- “Kho trung gian” có `location_type/type = ontheroad`: đây là kho ảo/tổng hợp, không đưa vào danh sách kho để nhập, điều chuyển hoặc chọn tồn.
- `is_unavailable_quantity: true` là kho không khả dụng; không cho chọn làm kho nhập/điều chuyển. Trường này khác `location_type`: kho vẫn có thể có `type: default` nhưng bị đánh dấu không khả dụng.
- Ở shop đang test, kho không khả dụng được dùng cho hàng hỏng/lỗi; đây là quy ước shop, không nên hard-code rằng mọi shop dùng kho này chỉ cho hàng hỏng.
- Khi không có dòng tồn cho cặp kho/biến thể, UI có thể hiển thị 0; phân biệt rõ “không có dòng tồn” với lỗi gọi API. Tài liệu hỗ trợ tối đa 50 ID kho và 50 ID variant mỗi request, nên cần chia batch.

### Ghi nhận nhập hàng / điều chỉnh tồn

- `POST /com/inventories/adjustorset.json` (proxy: `POST /inventories/adjustorset`) nhận body dạng:

  ```json
  {
    "inventory": {
      "location_id": 123,
      "type": "adjust",
      "reason": "newproduct",
      "note": "Ghi chú",
      "line_items": [
        {
          "product_id": 456,
          "product_variant_id": 789,
          "quantity": 2,
          "cost_amount": 35000
        }
      ]
    }
  }
  ```

- `location_id` là ID kho nhận thật. `product_id` và `product_variant_id` phải khớp nhau. Tài liệu nêu tối đa khoảng 200 dòng/request.
- `type: "adjust"` cộng/trừ lượng điều chỉnh theo API; `type: "set"` đặt tồn về số lượng chỉ định. Đây là **Inventory Adjustment/điều chỉnh tồn**, không phải phiếu nhập Purchase Receive. Không dùng endpoint này để giả lập nhập hàng.
- `reason` nhận các giá trị tài liệu liệt kê như `newproduct`, `returned`, `productionofgoods`, `damaged`, `shrinkage`, `promotion`; tài liệu có nêu `transfer` cho trường hợp chuyển kho. Không gửi nhãn tiếng Việt vào trường mã này.
- Response/lịch sử điều chỉnh cần giữ ý `id`, `adjust_number`, `location_id`, `type`, `reason`, `tran_date`, `total_quantity`, `total_cost`, `line_items`. `line_items` có `product_id`, `product_variant_id`, `quantity`, `cost_amount`, SKU/barcode nếu API trả.
- **FE hiện chỉ đọc và hiển thị Purchase Receive.** Form nhập hàng chưa được phép gửi dữ liệu vì tài liệu Purchase Receive hiện chỉ công bố GET; không chuyển form qua `adjustorset` vì endpoint đó chỉ điều chỉnh tồn.

### Kiểm kho dùng Inventory Adjustment của Haravan

- Danh sách kiểm kho đọc từ `GET /com/inventories/adjustments.json`; phân trang và đếm dữ liệu bằng `GET /com/inventories/adjustments/count.json`.
- Mở một dòng thì đọc lại chi tiết bằng `GET /com/inventories/adjustments/{id}.json`.
- Hoàn tất kiểm kho gửi các dòng chênh lệch qua `POST /com/inventories/adjustorset.json`. Gắn tag `kiem-kho` để phân biệt các điều chỉnh được tạo từ trang này; không lưu phiếu kiểm kho riêng trong MongoDB.
- Haravan chỉ tạo bản ghi điều chỉnh khi tồn có thay đổi; các dòng khớp không tạo phiếu riêng. Điều chỉnh tăng và giảm được gửi riêng vì `reason` áp dụng cho toàn request.
- API Adjustment không thay thế mọi kiểu tồn kho đặc biệt. Trước khi hỗ trợ hàng theo lô/hạn dùng, combo, tồn Basic Inventory hay số lượng lẻ, cần kiểm tra scope và tài liệu/API chuyên biệt.

### Lịch sử điều chỉnh

- `GET /com/inventories/adjustments.json` hỗ trợ `page`, `limit`, `since_id`, `location_id`; chi tiết: `/com/inventories/adjustments/{id}.json`; đếm: `/com/inventories/adjustments/count.json`.
- `location_id` trong lịch sử là kho của phiếu điều chỉnh, không phải ID variant. Muốn hiện tên kho thì map với `/locations.json`.
- Không lấy `total_cost` làm giá đơn vị; đây là tổng giá trị phiếu theo tài liệu. Dùng dòng `line_items.cost_amount` nếu cần giá vốn từng dòng.

### Phiếu nhập, đặt hàng, trả hàng nhập

- Purchase Receives: `GET /com/v2/inventories/purchase_receives.json` và `GET /com/v2/inventories/purchase_receives/{id}.json`. Theo tài liệu hiện có chỉ thấy GET; không tự giả định có POST tạo phiếu.
- Purchase Orders: `GET /com/inventories/purchase_orders.json` và `GET /com/inventories/purchase_orders/{id}.json`.
- Purchase Returns: `GET /com/v2/inventories/purchase_returns.json` và `GET /com/v2/inventories/purchase_returns/{id}.json`.
- Các response có thể chứa object lồng nhau `supplier`, `location`, `line_items`; code cần chịu được `supplier` dạng chuỗi hoặc object và `line_items` đơn hoặc mảng nếu response test thực tế khác tài liệu.
- Trạng thái mẫu gồm `Nháp`, `Đã nhập hàng`, `Đã xuất trả`, `Đã hủy`; nên giữ nguyên trạng thái Haravan để hiển thị, không tự suy ra trạng thái chỉ từ ngày tạo.

### Điều chuyển kho

- Danh sách/đếm: `GET /com/inventories/transfers.json`, `/com/inventories/transfers/count.json`; chi tiết theo tài liệu: `GET /com/inventorytransfer/detail/{id}.json`.
- Tạo: `POST /com/inventories/transfer.json`, body `{ "transfer": { "from_loc_id", "to_loc_id", "reason", "note", "line_items": [...] } }`. Hai kho phải khác nhau; line item dùng `product_id`, `product_variant_id`, `quantity`.
- Nhận hàng: `POST /com/inventories/transfer/{id}/receive.json`; ví dụ tài liệu gửi `{ "transfer": { "user_id": 3 } }`. Cần xác minh `user_id` là ID nhân viên Haravan hợp lệ cho shop trước khi bắt buộc gửi. FE hiện gửi `{ transfer: {} }`; nếu API báo thiếu user, cần lấy ID Haravan phù hợp (không gửi app user ID tùy tiện).
- Tài liệu có trường `from_loc_id`, `to_loc_id`, `total`, `status`, `received_at`, `line_items`; sau khi nhận phải tải lại phiếu để xác nhận trạng thái từ Haravan. Không chỉ dựa vào trạng thái tạm lưu ở trình duyệt.

## Sản phẩm và biến thể

- Product list/detail/create/update dùng `/products.json`, `/products/{id}.json`; variant dùng `/products/{product_id}/variants.json` và `/variants/{variant_id}.json`. Body ghi có wrapper `{ product: ... }` hoặc `{ variant: ... }`.
- Tồn variant như `inventory_quantity`/`inventory_advance` không nên dùng làm tồn tại kho cụ thể. Muốn biết tồn kho nào, truy vấn Inventory Locations theo `loc_id + variant_id`.
- Khi sửa biến thể, giữ các trường hiện có cần bảo toàn: `option1..3`, `sku`, `barcode`, `price`, `compare_at_price`, `inventory_management`, `inventory_policy`, `requires_shipping`, `taxable`, `image_id`, `variant_units`. Payload thiếu trường không đồng nghĩa API sẽ giữ nguyên trong mọi endpoint; đọc lại variant sau cập nhật.
- Đừng tự xóa biến thể cuối cùng hoặc sửa options mà không rà các biến thể khác; `product_id` và variant ID là định danh liên kết tồn kho/đơn hàng.
- Xóa product/variant là thao tác phá hủy và có thể ảnh hưởng liên kết; xác minh ID và dữ liệu phụ thuộc trước khi gọi DELETE.

## Khách hàng và địa chỉ

- Customer list/search/detail/create/update/delete dùng `/customers.json`, `/customers/search.json`, `/customers/{id}.json`; wrapper ghi là `{ customer: ... }`.
- Tìm khách bằng search API thay vì tải toàn bộ danh sách. Giữ `id` Haravan để tái sử dụng khách khi tạo đơn; không tạo khách mới nếu đã có customer ID.
- Địa chỉ customer là tài nguyên riêng `/customers/{customerId}/addresses...`; trường `default` có ý nghĩa riêng. Các thao tác `set`, `/default`, create/update/delete không thể thay thế lẫn nhau.
- Không gửi `null`, chuỗi rỗng hoặc địa chỉ chưa hoàn chỉnh để “xóa” trường nếu chưa xác nhận semantics của endpoint. Khi update, đọc lại customer/address để chắc trường nào được giữ, trường nào bị ghi đè.
- Tag customer/product dùng endpoint riêng `/tags.json`; cần xử lý chuỗi tag đúng format API, không giả định giống mảng tags trong mọi response.

## Đơn hàng

- Tạo đơn FE đi qua backend `/orders/{orgId}/create`, rồi backend gọi Haravan `POST /com/orders.json`; body API Haravan phải theo wrapper `{ order: ... }`. Lưu `id` Haravan trả về làm ID ngoài; không dùng ID Mongo làm ID gọi API Haravan.
- Nếu gửi `customer_id`, payload dùng tham chiếu `{ customer: { id } }`; chỉ gửi thông tin khách mới khi thực sự cần. Haravan có thể chỉ trả `customer.id`, nên backend giữ snapshot tên/email/điện thoại từ request khi response thiếu.
- Mã giảm giá, `discount_codes`, `total_discounts`, giảm giá từng dòng và giá trị Haravan tính có thể khác nhau. Khi API tạo đơn từ chối tổng tiền/discount, đối chiếu `line_items`, `total_discounts`, `discount_codes` và định nghĩa discount; không tự cộng giảm giá lần hai.
- `inventory_quantity` không xác định kho fulfillment của đơn. Kiểm tra trường location/fulfillment riêng nếu nghiệp vụ cần giao từ kho cụ thể.
- Xác nhận đơn gọi `POST /com/orders/{id}/confirm.json`. Trạng thái cuối cùng được đồng bộ từ webhook; response xác nhận không đảm bảo trạng thái local đã cập nhật ngay.
- Kiểm tra đơn thứ 2 trở đi dựa vào `customer.orders_count` từ webhook Haravan, không đếm số order local. `is_repeat_order = orders_count > 1`; webhook có thể đến lặp hoặc không đúng thứ tự, nên cập nhật phải idempotent và không để payload thiếu ghi đè dữ liệu đã có.

## Collection và Collect

- Collection là `/custom_collections`; collect là quan hệ sản phẩm trong collection `/collects`. Tạo/sửa/xóa collection không tự đảm bảo membership sản phẩm đúng.
- Nếu thêm/bỏ sản phẩm trong collection, gọi API Collect tương ứng và truyền đúng `collection_id` + `product_id`. Tránh tạo duplicate collect khi retry; tải lại list để kiểm tra.
- Smart collection và custom collection có quy tắc khác nhau; không giả định API có thể chỉnh membership thủ công cho cả hai loại.

## Discount và Promotion

- Discount endpoints và Promotion endpoints nằm ở service/controller riêng. Có thao tác enable/disable và delete; enable/disable không đồng nghĩa tạo/sửa định nghĩa promotion.
- API order cần coupon code có thể phải tra `/discounts.json?code=...` để lấy `discount_type`, `value`, phạm vi áp dụng. Kiểm tra hạn dùng, trạng thái, sản phẩm/collection áp dụng, giới hạn số lần trước khi tự tính amount.
- Phân biệt phần trăm (`percentage`) và số tiền cố định (`fixed_amount`); đơn vị tiền dùng cùng currency của shop. Không tin amount FE nếu Haravan trả giá trị tính cuối khác.

## OAuth và webhook

- OAuth đổi code tại `https://accounts.haravan.com/connect/token`; `redirect_uri` khi đổi code phải giống chính xác URI đã dùng khi xin quyền. Kiểm tra scope thực tế trong token response và lưu đúng `orgId`.
- Omni API dùng token của shop; API quản lý đăng ký webhook gọi host riêng `/api/subscribe` với Bearer token và cần `wh_api`. Không nhầm endpoint này với Omni `/com/...`.
- App webhook và private webhook có cơ chế xác thực HMAC riêng. Không sửa thứ tự/encoding raw body trước khi tính HMAC; sai secret hoặc dùng JSON đã parse lại sẽ làm chữ ký sai.
- Webhook có thể gửi trùng, gửi chậm hoặc thiếu một số trường. Lưu event trước khi xử lý, dùng ID/topic để idempotency, merge các trường có giá trị thay vì ghi đè toàn bộ document bằng payload thiếu.
- Không ghi access token, client secret, webhook secret hoặc payload có PII vào note/log chia sẻ. Nếu cần debug, che token, email/điện thoại và địa chỉ.

## API chưa được xác nhận / cần test trước khi mở tính năng

- Tạo Purchase Receive và Purchase Return: tài liệu hiện lưu trong `inventory.md` chỉ mô tả GET.
- Nhà cung cấp và kiểm kho: chưa có endpoint tương ứng trong tài liệu hiện tại.
- Nhận điều chuyển: xác minh body `user_id` với shop thật; hiện FE gửi object rỗng.
- Các phản hồi lỗi/thành công thực tế có thể dùng wrapper khác nhau (`adjustment`/`inventory_adjustment`, `transfers`/tên khác). Trước khi mở rộng type, lưu mẫu JSON đã ẩn thông tin nhạy cảm và cập nhật type/parser cùng lúc.

## Khi test Postman

1. Gọi qua proxy backend để kiểm tra org/token, hoặc gọi Haravan trực tiếp với access token shop và đúng host `/com/...`.
2. Dùng một ID đã lấy từ chính shop đó; lấy kho từ `locations.json`, variant từ product detail.
3. Với ghi tồn/điều chuyển, thử số lượng nhỏ ở kho test và GET lại tồn/phiếu sau khi POST.
4. Lưu request/response thành mẫu đã che token, email, số điện thoại, địa chỉ và các thông tin cá nhân.
5. Ghi rõ endpoint, scope, status, wrapper request, wrapper response, ngày test và shop/môi trường.

