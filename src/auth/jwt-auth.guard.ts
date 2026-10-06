import {
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { IS_PUBLIC_KEY } from 'src/decorators/customize';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    // Lấy metadata từ yêu cầu.
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }
    return super.canActivate(context);
  }

  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    // if (user?.email === "admin@gmail.com" || user?.name === "admin") return user;
    const request: Request = context.switchToHttp().getRequest();
    // Có thể tạo ngoại lệ dựa trên tham số "info" hoặc "err".
    if (err || !user) {
      throw (
        err ||
        new UnauthorizedException(
          'Your token is invalid or header is missing token',
        )
      );
    }
    if (user.isBan) {
      throw new ForbiddenException('You is Ban');
    }

    return user;
  }
}
