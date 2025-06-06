import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { KmsKeyCacheService } from './kms-key-cache.service';
import * as crypto from 'crypto';

@Injectable()
export class KmsJwtService {
  private jwtIssuer: string;
  private jwtAudience: string;
  private jwtAlgorithm: string;
  private jwtExpiresInSeconds: number;
  private kmsKeyVersionName: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly kmsKeyCacheService: KmsKeyCacheService,
  ) {
    this.jwtIssuer = this.configService.get<string>('JWT_ISSUER');
    this.jwtAudience = this.configService.get<string>('JWT_AUDIENCE');
    this.jwtAlgorithm = this.configService.get<string>('JWT_ALGORITHM', 'ES256');
    const expiresInStr = this.configService.get<string>('JWT_SESSION_EXPIRES_IN', '7d');
    if (expiresInStr.endsWith('d')) {
      this.jwtExpiresInSeconds = parseInt(expiresInStr.slice(0, -1), 10) * 24 * 60 * 60;
    } else if (expiresInStr.endsWith('h')) {
      this.jwtExpiresInSeconds = parseInt(expiresInStr.slice(0, -1), 10) * 60 * 60;
    } else {
      this.jwtExpiresInSeconds = parseInt(expiresInStr, 10);
    }
    this.kmsKeyVersionName = this.configService.get<string>('KMS_SIGNING_KEY_ID');
  }

  async signKmsJwt(payload: Record<string, any>): Promise<string> {
    // Get the current versioned key and public key from the shared cache service
    const { versionId } = await this.kmsKeyCacheService.getCurrentPublicKeyByKeyId(this.kmsKeyVersionName);
    const header = {
      alg: this.jwtAlgorithm,
      typ: 'JWT',
      kid: versionId,
    };
    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + this.jwtExpiresInSeconds;
    const fullPayload = {
      ...payload,
      iss: this.jwtIssuer,
      aud: this.jwtAudience,
      iat,
      exp,
    };
    const segments: string[] = [];
    segments.push(Buffer.from(JSON.stringify(header)).toString('base64url'));
    segments.push(Buffer.from(JSON.stringify(fullPayload)).toString('base64url'));
    const dataToSign = segments.join('.');
    let digest: { sha256?: Buffer };
    if (this.jwtAlgorithm.startsWith('RS') || this.jwtAlgorithm.startsWith('PS') || this.jwtAlgorithm.startsWith('ES')) {
      const hash = crypto.createHash('sha256');
      hash.update(dataToSign);
      digest = { sha256: hash.digest() };
    } else {
      throw new InternalServerErrorException(`Unsupported signing algorithm for KMS: ${this.jwtAlgorithm}`);
    }
    try {
      // Use the versioned key id for signing
      const [signResponse] = await this.kmsKeyCacheService['kmsClient'].asymmetricSign({
        name: versionId,
        digest: digest,
      });
      if (!signResponse.signature) {
        throw new Error('KMS did not return a signature.');
      }
      segments.push(Buffer.from(signResponse.signature).toString('base64url'));
      return segments.join('.');
    } catch (error) {
      console.error('Error signing JWT with KMS:', error);
      throw new InternalServerErrorException('Failed to sign session token.');
    }
  }
}
