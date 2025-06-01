import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

// Define the expected payload structure of your session JWT
export interface SessionJwtPayload {
  sub: string; // Typically the app_user_id
  email: string;
  // Add other fields you included in the JWT payload during login
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt-session') {
  constructor(private readonly configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => {
          let token = null;
          if (request && request.cookies) {
            token = request.cookies['session_token'];
          }
          return token;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SESSION_SECRET'),
    });
  }

  async validate(payload: SessionJwtPayload): Promise<SessionJwtPayload> {
    if (!payload || !payload.sub) {
      throw new UnauthorizedException('Invalid session token payload.');
    }
    return payload;
  }
}
