import {
  createParamDecorator,
  SetMetadata,
  ExecutionContext,
} from '@nestjs/common';
import aqp from 'api-query-params';

// truyền thêm metadata vào lời gọi hàm
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true); // key:value

export const RESPONSE_MESSAGE = 'response_message';
export const ResponseMessage = (message: string) =>
  SetMetadata(RESPONSE_MESSAGE, message);

export const User = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) =>
    ctx.switchToHttp().getRequest().user,
);
