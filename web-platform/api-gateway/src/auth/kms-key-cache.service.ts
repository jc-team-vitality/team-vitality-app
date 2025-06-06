import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { KeyManagementServiceClient, v1 } from '@google-cloud/kms';
interface CachedVersion {
  versionId: string;
  algorithm: string;
  expiresAt: number;
}

@Injectable()
export class KmsKeyCacheService {
  private kmsClient = new KeyManagementServiceClient();
  // Cache for public keys by versioned resource id (never expires)
  private publicKeyCache = new Map<string, string>();
  // Cache for current version id by non-versioned key id (with TTL)
  private versionIdCache = new Map<string, CachedVersion>();
  private versionIdTtlMs = 10 * 60 * 1000; // 10 minutes default TTL

  setVersionIdTtl(ttlMs: number) {
    this.versionIdTtlMs = ttlMs;
  }

  async getPublicKeyByVersion(versionedResourceId: string): Promise<string> {
    if (this.publicKeyCache.has(versionedResourceId)) {
      return this.publicKeyCache.get(versionedResourceId)!;
    }
    const [publicKeyResponse] = await this.kmsClient.getPublicKey({ name: versionedResourceId });
    if (!publicKeyResponse.pem) {
      throw new InternalServerErrorException('Failed to retrieve public key from KMS');
    }
    this.publicKeyCache.set(versionedResourceId, publicKeyResponse.pem);
    return publicKeyResponse.pem;
  }

  async getCurrentPublicKeyByKeyId(keyId: string): Promise<{ versionId: string, alg: string }> {
    let cached = this.versionIdCache.get(keyId);
    const now = Date.now();
    if (!cached || cached.expiresAt < now) {
      // Fetch key metadata to get the current version

      const [key] = await this.kmsClient.getCryptoKey({ name: keyId });
      if (!key.primary || !key.primary.name) {
        throw new InternalServerErrorException('Failed to get primary version for KMS key');
      }

      function mapAlgorithm(alg?: string): string {
        if (!alg) return '';
        if (alg.startsWith('RSA_SIGN_PKCS1_')) {
          return alg
            .replace('RSA_SIGN_PKCS1_', 'RS')
            .replace('_SHA_256', '256')
            .replace('_SHA_384', '384')
            .replace('_SHA_512', '512');
        }
        if (alg.startsWith('EC_SIGN_P256_SHA256')) {
          return 'ES256';
        }
        if (alg.startsWith('EC_SIGN_P384_SHA384')) {
          return 'ES384';
        }
        if (alg.startsWith('EC_SIGN_P521_SHA512')) {
          return 'ES512';
        }
        return alg;
      }
      cached = {
        versionId: key.primary.name,
        algorithm: mapAlgorithm(String(key.primary.algorithm)),
        expiresAt: now + this.versionIdTtlMs // TODO: use the actual next rotation time if available
      };
      this.versionIdCache.set(keyId, cached);
    }
    return { versionId: cached.versionId, alg: cached.algorithm };
  }
}
