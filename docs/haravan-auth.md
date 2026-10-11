# Đăng nhập qua Haravan (Haravan Connect / OpenID Connect)

Cho phép đăng nhập bằng tài khoản Haravan (OpenID Connect) thay vì số điện
thoại + mật khẩu. Module: `src/haravan-auth/`.

Tài liệu Haravan: [Node.js OpenID Client](https://docs.haravan.com/docs/tutorials/authentication/node-js-openid-client/)

## Luồng

```
GET /api/v1/haravan/auth/login          (302 -> accounts.haravan.com/connect/authorize)
POST /api/v1/haravan/auth/callback      (Haravan gui code bang form_post)
POST /api/v1/haravan/auth/session       (frontend doi ticket -> access/refresh token)
GET /api/v1/haravan/auth/me             (user + thong tin Haravan da lien ket)
GET /api/v1/haravan/auth/logout         (huy token noi bo, tra URL logout Haravan)
```

Mặc định dùng **Authorization Code Flow + PKCE** (`response_type=code`,
`code_challenge_method=S256`). `openid-client` tự kiểm tra chữ ký id_token
 qua JWKS, `nonce`, `state`, `iss`, `aud`.

### Hai kiểu nhận token

| Cách | Khi nào | Kết quả |
| --- | --- | --- |
| Callback trả JSON | Không khai báo `HARAVAN_OPENID_FRONTEND_REDIRECT_URI` (mobile, Postman) | `{ user, token: { access_token, refresh_token }, haravan }` |
| Callback chuyển hướng | Có `HARAVAN_OPENID_FRONTEND_REDIRECT_URI` | 302 về frontend kèm `?code=<ticket>` (mã dùng một lần), frontend gọi `POST /haravan/auth/session` để lấy token |

Ticket dùng một lần và hết hạn sau `HARAVAN_OPENID_STATE_TTL_MS`, nhờ vậy
không lộ access token trong query string / log của proxy.

## Cấu hình

Xem `.env.example` mục *Đăng nhập bằng tài khoản Haravan*. Biến bắt buộc:

```
HARAVAN_OPENID_ENABLED=true
HARAVAN_OPENID_CLIENT_ID=...        # fallback sang HARAVAN_CLIENT_ID
HARAVAN_OPENID_CLIENT_SECRET=...    # fallback sang HARAVAN_CLIENT_SECRET
HARAVAN_OPENID_REDIRECT_URI=https://domain.com/api/v1/haravan/auth/callback
```

`redirect_uri` phải đăng ký **chính xác** ở Haravan Partner Dashboard (không
thêm query string), và phải là URL công khai (dùng ngrok khi dev).

Tuỳ chọn:

| Biến | Mặc định | Ý nghĩa |
| --- | --- | --- |
| `HARAVAN_OPENID_ISSUER` | `https://accounts.haravan.com` | Issuer OIDC |
| `HARAVAN_OPENID_SCOPE` | `openid profile email org` | `org` để có claim `orgid` |
| `HARAVAN_OPENID_RESPONSE_TYPE` | `code` | Đổi sang `code id_token` nếu dashboard yêu cầu hybrid |
| `HARAVAN_OPENID_FRONTEND_REDIRECT_URI` | rỗng | Trang web quay về sau khi đăng nhập |
| `HARAVAN_OPENID_ALLOWED_REDIRECT_HOSTS` | rỗng | Cho phép `?redirect_uri=` của frontend |
| `HARAVAN_OPENID_ORG_ID` | rỗng | Chỉ cho shop này đăng nhập |
| `HARAVAN_OPENID_AUTO_PROVISION` | `true` | Tự tạo user ở lần đăng nhập đầu tiên |
| `HARAVAN_OPENID_DEFAULT_ROLE` | `Assistant Admin` | Vai trò của user mới (phải có trong `roles`) |
| `HARAVAN_OPENID_STATE_TTL_MS` | `600000` | Hạn của state/ticket |

## Ánh xạ người dùng

`HaravanIdentityService` tìm user nội bộ theo thứ tự:

1. `users.haravanUserId === sub` (claim `sub` của id_token)
2. `users.haravanEmail === email` → gắn liên kết vào user đó
3. Nếu `HARAVAN_OPENID_AUTO_PROVISION=true` → tạo user mới:
   - `phone = haravan-<sub>` (giá trị giả, không dùng để đăng nhập)
   - `role = HARAVAN_OPENID_DEFAULT_ROLE`
   - `haravanOrgId` lấy từ claim `orgid`

Người dùng tạo bởi Haravan **không đăng nhập được bằng mật khẩu**; nếu muốn
cả hai cách thì đặt mật khẩu thật qua `PATCH /api/v1/auth/change-password`.

## Ghi chú

- `state`, `nonce` và ticket lưu trong RAM tiến trình (mặc định 10 phút, dùng
  một lần). Khi chạy nhiều instance, request callback có thể rơi vào instance
  khác và phải đăng nhập lại.
- `POST /haravan/auth/callback` phải nhận được `application/x-www-form-urlencoded`
  (Nest đã bật sẵn) vì Haravan dùng `response_mode=form_post`.
- Logout phía Haravan (`https://accounts.haravan.com/connect/endsession`) chỉ
  có tác dụng đầy đủ nếu BE giữ `id_token`; hiện tại `/logout` chỉ hủy token
  nội bộ và trả về URL để người dùng mở.
