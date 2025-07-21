import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const GetPaginateInfo = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const page = Number(request.query.page) || 1; // Trang hiện tại (mặc định là 1)
    const limit = Number(request.query.limit) || 10; // Số lượng mục trên mỗi trang (mặc định là 10)

    const offset = (page - 1) * limit; // Tính toán offset để phân trang

    return { page, limit, offset };
  },
);
