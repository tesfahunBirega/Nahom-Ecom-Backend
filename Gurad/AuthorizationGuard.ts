import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

@Injectable()
export class AuthorizationGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const permission = this.reflector.get<string[]>(
      'permission',
      context.getHandler(),
    );
    const request = context.switchToHttp().getRequest();

    // Check if user is authenticated and has necessary properties
    if (!request.user || !request.user.role || !request.user.role.permissions) {
      throw new UnauthorizedException('Invalid user or missing permissions');
    }

    // Check user permissions
    const userPermissions = request.user.role.permissions;
    const hasPermission = userPermissions.some(
      (item) => item.slug === permission.toString(),
    );

    if (!hasPermission) {
      throw new UnauthorizedException('Insufficient permissions');
    }

    return true;
  }
}
