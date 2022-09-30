import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly authService: AuthService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req: any = this.getRequest(context);

    try {
      const token = this.getToken(req);
      const user = this.jwtService.verify(token);
      const serializedUser = await this.authService.findUser(
        `${user.sub}`,
      );

      req.user = {
        ...user,
        roles: serializedUser.roles,
      };
      return true;
    } catch (err) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  protected getRequest<T>(context: ExecutionContext): T {
    return context.switchToHttp().getRequest();
  }

  protected getToken(req: {
    headers: Record<string, string | string>;
  }): string {
    const authorization = req.headers['authorization'];

    if (!authorization || Array.isArray(authorization))
      throw new UnauthorizedException('No authorization header');

    const [_, token] = authorization.split(' ');

    if (!token) throw new UnauthorizedException('No token');

    return token;
  }
}
