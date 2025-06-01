import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { GoogleAuth } from 'google-auth-library';
import { firstValueFrom } from 'rxjs';
import { OIDCTokenExchangeResponse } from './oidc-token-exchange-response.interface';

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
}
