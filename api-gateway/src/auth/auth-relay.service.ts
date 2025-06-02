import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { GoogleAuth } from 'google-auth-library';
import { firstValueFrom } from 'rxjs';
import { OIDCTokenExchangeResponse } from './oidc-token-exchange-response.interface';
import { IdentityProviderConfigDto, IdentityProviderConfigCreateDto, IdentityProviderConfigUpdateDto } from '@teamvitality/shared-dtos';

@Injectable()
export class AuthRelayService {
  private googleAuth: GoogleAuth;
  private authServiceBaseUrl: string;

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    this.googleAuth = new GoogleAuth();
    this.authServiceBaseUrl = this.configService.get<string>('AUTH_SERVICE_BASE_URL');
  }

  private async getAuthServiceIdToken(): Promise<string> {
    try {
      const client = await this.googleAuth.getIdTokenClient(this.authServiceBaseUrl);
      const headers = await client.getRequestHeaders(this.authServiceBaseUrl);
      if (headers && headers.Authorization) {
        return headers.Authorization.replace('Bearer ', '');
      }
      throw new Error('Failed to obtain ID token for auth-service');
    } catch (error) {
      console.error('Error fetching ID token for auth-service:', error);
      throw new InternalServerErrorException('Failed to prepare authentication with internal service.');
    }
  }

  async initiateLogin(providerName: string): Promise<{ authorizationUrl: string; state: string }> {
    const targetUrl = `${this.authServiceBaseUrl}/oidc/initiate-login/${providerName}`;
    try {
      const idToken = await this.getAuthServiceIdToken();
      const response = await firstValueFrom(
        this.httpService.post(
          targetUrl,
          {},
          { headers: { Authorization: `Bearer ${idToken}` } },
        ),
      );
      return { authorizationUrl: response.data.authorization_url, state: response.data.state };
    } catch (error) {
      console.error(`Error calling auth-service initiate-login for ${providerName}:`, error.response?.data || error.message);
      throw new InternalServerErrorException('Login initiation failed.');
    }
  }

  async exchangeCodeForToken(code: string, state: string): Promise<OIDCTokenExchangeResponse> {
    const targetUrl = `${this.authServiceBaseUrl}/oidc/token/exchange`;
    try {
      const idToken = await this.getAuthServiceIdToken();
      const response = await firstValueFrom(
        this.httpService.post(
          targetUrl,
          { authorization_code: code, state: state },
          { headers: { Authorization: `Bearer ${idToken}` } },
        ),
      );
      return response.data;
    } catch (error) {
      console.error('Error calling auth-service token exchange:', error.response?.data || error.message);
      throw new InternalServerErrorException('Authentication failed during token exchange with auth service.');
    }
  }

  async initiateAccountLink(
    providerName: string,
    appUserId: string
  ): Promise<{ authorizationUrl: string; state: string }> {
    const targetUrl = `${this.authServiceBaseUrl}/oidc/link-account/initiate/${providerName}`;
    try {
      const idToken = await this.getAuthServiceIdToken();
      const response = await firstValueFrom(
        this.httpService.post(
          targetUrl,
          { app_user_id: appUserId },
          { headers: { Authorization: `Bearer ${idToken}` } },
        ),
      );
      if (response.data && response.data.authorization_url && response.data.state) {
        return {
          authorizationUrl: response.data.authorization_url,
          state: response.data.state,
        };
      } else {
        throw new Error('Invalid response structure from auth-service for account link initiation.');
      }
    } catch (error) {
      console.error(`Error calling auth-service initiate-account-link for ${providerName}, user ${appUserId}:`, error.response?.data || error.message);
      throw new InternalServerErrorException('Account linking initiation failed.');
    }
  }

  async createIdpConfig(createDto: IdentityProviderConfigCreateDto): Promise<IdentityProviderConfigDto> {
    const targetUrl = `${this.authServiceBaseUrl}/admin/identity-providers/`;
    const idToken = await this.getAuthServiceIdToken();
    try {
      const response = await firstValueFrom(
        this.httpService.post(targetUrl, createDto, {
          headers: { Authorization: `Bearer ${idToken}` },
        }),
      );
      return response.data;
    } catch (error) {
      console.error('Error calling auth-service createIdpConfig:', error.response?.data || error.message);
      throw new InternalServerErrorException('Failed to create IdP configuration.');
    }
  }

  async listIdpConfigs(skip: number = 0, limit: number = 100): Promise<IdentityProviderConfigDto[]> {
    const targetUrl = `${this.authServiceBaseUrl}/admin/identity-providers/?skip=${skip}&limit=${limit}`;
    const idToken = await this.getAuthServiceIdToken();
    try {
      const response = await firstValueFrom(
        this.httpService.get(targetUrl, {
          headers: { Authorization: `Bearer ${idToken}` },
        }),
      );
      return response.data;
    } catch (error) {
      console.error('Error calling auth-service listIdpConfigs:', error.response?.data || error.message);
      throw new InternalServerErrorException('Failed to list IdP configurations.');
    }
  }

  async getIdpConfig(providerId: string): Promise<IdentityProviderConfigDto> {
    const targetUrl = `${this.authServiceBaseUrl}/admin/identity-providers/${providerId}`;
    const idToken = await this.getAuthServiceIdToken();
    try {
      const response = await firstValueFrom(
        this.httpService.get(targetUrl, {
          headers: { Authorization: `Bearer ${idToken}` },
        }),
      );
      return response.data;
    } catch (error) {
      console.error(`Error calling auth-service getIdpConfig for ${providerId}:`, error.response?.data || error.message);
      throw new InternalServerErrorException('Failed to retrieve IdP configuration.');
    }
  }

  async updateIdpConfig(providerId: string, updateDto: IdentityProviderConfigUpdateDto): Promise<IdentityProviderConfigDto> {
    const targetUrl = `${this.authServiceBaseUrl}/admin/identity-providers/${providerId}`;
    const idToken = await this.getAuthServiceIdToken();
    try {
      const response = await firstValueFrom(
        this.httpService.put(targetUrl, updateDto, {
          headers: { Authorization: `Bearer ${idToken}` },
        }),
      );
      return response.data;
    } catch (error) {
      console.error(`Error calling auth-service updateIdpConfig for ${providerId}:`, error.response?.data || error.message);
      throw new InternalServerErrorException('Failed to update IdP configuration.');
    }
  }

  async deleteIdpConfig(providerId: string): Promise<void> {
    const targetUrl = `${this.authServiceBaseUrl}/admin/identity-providers/${providerId}`;
    const idToken = await this.getAuthServiceIdToken();
    try {
      await firstValueFrom(
        this.httpService.delete(targetUrl, {
          headers: { Authorization: `Bearer ${idToken}` },
        }),
      );
    } catch (error) {
      console.error(`Error calling auth-service deleteIdpConfig for ${providerId}:`, error.response?.data || error.message);
      throw new InternalServerErrorException('Failed to delete IdP configuration.');
    }
  }
}
