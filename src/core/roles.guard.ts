import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from 'src/decorators/roles.decorator'; // Để lấy giá trị của decorator

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean | Promise<boolean> {
    const requiredRoles = this.reflector.get<string[]>(
      ROLES_KEY,
      context.getHandler(),
    ); // Lấy metadata
    if (!requiredRoles) {
      return true; // Nếu không có vai trò yêu cầu, cho phép truy cập
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user; // Giả sử user đã được gắn vào request từ @User() decorator

    if (!user || !requiredRoles.includes(user.role)) {
      throw new ForbiddenException('You do not have permission');
    }

    return true; // Nếu user có quyền, cho phép truy cập
  }
}
