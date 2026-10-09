import { ApiClient } from './api.service';
import { compactQuery, mapHaravanError } from './haravan.util';

/**
 * Lớp nền cho các service proxy tài nguyên Haravan.
 * Chỉ giữ phần gọi HTTP; mỗi tài nguyên (sản phẩm, kho, khách hàng...)
 * có một service riêng kế thừa lớp này và chứa đúng các endpoint của tài nguyên đó.
 */
export abstract class HaravanGateway {
  constructor(protected readonly api: ApiClient) {}

  /** Gọi Omni API và trả về phần body của response. */
  public async forward(
    orgId: number,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    path: string,
    body?: object,
    query?: object,
  ) {
    try {
      const res = await this.api.call(
        orgId,
        method,
        path,
        body as Record<string, unknown> | undefined,
        query ? compactQuery(query as Record<string, unknown>) : undefined,
      );
      return res.body;
    } catch (error) {
      mapHaravanError(error);
    }
  }
}
