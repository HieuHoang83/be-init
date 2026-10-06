import {
  createParamDecorator,
  SetMetadata,
  ExecutionContext,
} from '@nestjs/common';
import aqp from 'api-query-params';

// Gắn thêm metadata vào hàm.
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true); // Đánh dấu tuyến công khai.

export const RESPONSE_MESSAGE = 'response_message';
export const ResponseMessage = (message: string) =>
  SetMetadata(RESPONSE_MESSAGE, message);

export const User = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) =>
    ctx.switchToHttp().getRequest().user,
);
