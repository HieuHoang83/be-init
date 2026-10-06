/** Response chung cua webhook.haravan.com/api/subscribe */
export interface WebhookSubscribeResponse {
  error: boolean;
  message: string;
  error_Code?: string | null;
}

/** GET /api/subscribe - danh sach topic dang duoc subscribe */
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
