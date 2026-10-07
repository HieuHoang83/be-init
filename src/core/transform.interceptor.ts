import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { RESPONSE_MESSAGE } from 'src/decorators/customize';

export interface Response<T> {
  statusCode: number;
  message?: string;
  data: any;
}

// Chuyển đổi phản hồi sang định dạng thống nhất.
@Injectable()
export class TransformInterceptor<T>
  implements NestInterceptor<T, Response<T>>
{
  constructor(private reflector: Reflector) {}
  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<Response<T>> {
    const request = context.switchToHttp().getRequest();

    // Không chuyển đổi trang EJS hoặc yêu cầu tệp tĩnh.
    const isStaticAsset =
      request.url.startsWith('/public/') || request.url.startsWith('/assets/');
    const accept = request.headers?.accept || '';
    const isViewRoute =
      request.url.endsWith('.ejs') ||
      request.url.startsWith('/views/') ||
      accept.includes('text/html');
    // Webhook Haravan cần trả dữ liệu gốc để xác thực challenge và HMAC.
    const isWebhookRoute = request.url.includes('/webhooks/haravan');

    if (isStaticAsset || isViewRoute) {
      return next.handle(); // Bỏ qua tệp tĩnh và trang giao diện.
    }
    return next.handle().pipe(
      map((data) => ({
        statusCode: context.switchToHttp().getResponse().statusCode,
        message:
          this.reflector.get<string>(RESPONSE_MESSAGE, context.getHandler()) ||
          '',
        data: data,
      })),
    );
  }
}
