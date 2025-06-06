import { Injectable, UnauthorizedException, InternalServerErrorException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { KmsKeyCacheService } from './kms-key-cache.service';
import * as jwt from 'jsonwebtoken';
import { Algorithm } from 'jsonwebtoken';

// Define the expected payload structure of your session JWT
export interface SessionJwtPayload {
  sub: string; // Typically the app_user_id
  email: string;
  roles: string[]; // Add this line for user roles
  iss?: string;
  aud?: string;
  iat?: number;
  exp?: number;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt-session') {
  constructor(
    private readonly configService: ConfigService,
    private readonly kmsKeyCacheService: KmsKeyCacheService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => request?.cookies?.['session_token'],
      ]),
      ignoreExpiration: false,
      secretOrKeyProvider: async (request: Request, rawJwtToken: any, done: (err: any, secretOrKey?: string) => void) => {
        try {
          const unverifiedToken = jwt.decode(rawJwtToken, { complete: true }) as { header: { kid?: string } } | null;
          if (!unverifiedToken || typeof unverifiedToken === 'string' || !unverifiedToken.header.kid) {
            return done(new UnauthorizedException('Token missing kid in header'), undefined);
          }
          const kid = unverifiedToken.header.kid;
          // Use the shared cache service to get the public key by versioned resource id
          const publicKeyPem = await this.kmsKeyCacheService.getPublicKeyByVersion(kid);
          return done(null, publicKeyPem);
        } catch (error) {
          console.error('Error in secretOrKeyProvider (KMS public key fetch):', error);
          return done(error, undefined);
        }
      },
      issuer: configService.get<string>('JWT_ISSUER'),
      audience: configService.get<string>('JWT_AUDIENCE'),
      algorithms: [configService.get<string>('JWT_ALGORITHM', 'RS256') as Algorithm],
    });
  }

  async validate(payload: SessionJwtPayload): Promise<SessionJwtPayload> {
    if (!payload || !payload.sub) {
      throw new UnauthorizedException('Invalid session token payload.');
    }
    return payload;
  }
}
