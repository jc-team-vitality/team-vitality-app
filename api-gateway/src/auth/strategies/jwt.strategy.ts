import { Injectable, UnauthorizedException, InternalServerErrorException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { KeyManagementServiceClient } from '@google-cloud/kms';
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

const publicKeyCache = new Map<string, { key: string; expiresAt: number }>();

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt-session') {
  private kmsClient: KeyManagementServiceClient;

  constructor(private readonly configService: ConfigService) {
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
          const cachedEntry = publicKeyCache.get(kid);
          if (cachedEntry && cachedEntry.expiresAt > Date.now()) {
            return done(null, cachedEntry.key);
          }
          const [publicKeyResponse] = await this.kmsClient.getPublicKey({ name: kid });
          if (!publicKeyResponse.pem) {
            return done(new InternalServerErrorException('Failed to retrieve public key from KMS'), undefined);
          }
          const publicKeyPem = publicKeyResponse.pem;
          publicKeyCache.set(kid, { key: publicKeyPem, expiresAt: Date.now() + 3600 * 1000 });
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
    this.kmsClient = new KeyManagementServiceClient();
  }

  async validate(payload: SessionJwtPayload): Promise<SessionJwtPayload> {
    if (!payload || !payload.sub) {
      throw new UnauthorizedException('Invalid session token payload.');
    }
    return payload;
  }
}
