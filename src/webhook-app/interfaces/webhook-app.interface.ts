/** Cấu trúc phản hồi chung của webhook.haravan.com/api/subscribe. */
export interface WebhookSubscribeResponse {
  error: boolean;
  message: string;
  error_Code?: string | null;
}

/** Danh sách chủ đề webhook đã đăng ký từ GET /api/subscribe. */
export interface SubscribedWebhook {
  id: string;
  event: string;
  url: string;
}

export interface SubscribedWebhookListResponse {
  data: SubscribedWebhook[];
  error: boolean;
  message: string;
  error_Code?: string | null;
}
