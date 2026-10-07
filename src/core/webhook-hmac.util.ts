import { createHmac, timingSafeEqual } from 'crypto';

export const HMAC_HEADER = 'x-haravan-hmacsha256';

/**
 * Tính HMAC-SHA256 rồi mã hóa kết quả bằng Base64.
 *
 * Haravan ky webhook bang header `X-Haravan-Hmacsha256` =
 *   base64(HMAC_SHA256(raw_body, client_secret))
 *
 * PHẢI dùng raw body (byte-for-byte) chứ không phải JSON đã stringify lại,
 * nên Nest phải bật `rawBody: true` ở main.ts.
 */
export function computeHmac(
  rawBody: Buffer | string,
  clientSecret: string,
): string {
  return createHmac('sha256', clientSecret).update(rawBody).digest('base64');
}

/**
 * So sánh HMAC an toàn trước tấn công đo thời gian.
 * Trả về `false` nếu độ dài chuỗi không khớp.
 */
export function verifyHmac(
  rawBody: Buffer | string,
  clientSecret: string,
  received: string | undefined | null,
): boolean {
  if (!received || !clientSecret) return false;

  const expected = Buffer.from(computeHmac(rawBody, clientSecret), 'utf8');
  const actual = Buffer.from(String(received).trim(), 'utf8');

  if (expected.length !== actual.length) return false;

  return timingSafeEqual(expected, actual);
}
