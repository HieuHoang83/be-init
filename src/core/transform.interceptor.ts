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

// it will transform the response to the format we want
@Injectable()
export class TransformInterceptor<T>
  implements NestInterceptor<T, Response<T>> {
  constructor(private reflector : Reflector) {}
  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<Response<T>> {
    const request = context.switchToHttp().getRequest();

    // Exclude EJS views and static asset requests from transformation
    const isStaticAsset = request.url.startsWith('/public/') || request.url.startsWith('/assets/');
    const isViewRoute = request.url.endsWith('.ejs') || request.url.startsWith('/views/') || request.headers.accept.includes('text/html');

    if (isStaticAsset || isViewRoute) {
      return next.handle(); // Don't transform for static files or views
    }
    return next
      .handle()
      .pipe(
        map((data) => ({
          statusCode: context.switchToHttp().getResponse().statusCode,
          message: this.reflector.get<string>(RESPONSE_MESSAGE, context.getHandler()) || '',
          data: data
        })),
      );
  }
}