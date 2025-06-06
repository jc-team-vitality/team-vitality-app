import { Controller, Get, Param, Res, Req, Query, UnauthorizedException, Post, InternalServerErrorException, UseGuards } from '@nestjs/common';
import { Response, Request } from 'express';
import { AuthRelayService } from './auth-relay.service';
import { ConfigService } from '@nestjs/config';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { SessionJwtPayload } from './strategies/jwt.strategy';
import { KmsJwtService } from './kms-jwt.service';

// Module-level config key constants (shortened)
const ERROR_REDIRECT = 'FRONTEND_ERROR_REDIRECT_URL';
const LOGIN_SUCCESS_REDIRECT = 'FRONTEND_LOGIN_SUCCESS_REDIRECT_URL';
const SESSION_MAX_AGE = 'JWT_SESSION_MAX_AGE_SECONDS';
const ENV = 'NODE_ENV';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authRelayService: AuthRelayService,
    private readonly kmsJwtService: KmsJwtService,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Helper to handle redirects for success and error cases in OIDC callback.
   * @param res Express response
   * @param configKey ConfigService key for the redirect URL
   * @param errorCode Optional error code to append as ?code=...
   * @param defaultUri Default URI if config is missing (default: '/')
   */
  private handleRedirect(res: Response, configKey: string, errorCode?: string, defaultUri: string = '/'): any {
    const baseUri = this.configService.get<string>(configKey, defaultUri);
    const url = new URL(baseUri, 'http://dummy-base');
    if (errorCode) {
      url.searchParams.set('code', errorCode);
    }
    return res.redirect(url.pathname + url.search);
  }

  @Get('login/:providerName')
  async login(@Param('providerName') providerName: string, @Res() res: Response, @Req() req: Request) {
    try {
      const { authorizationUrl, state } = await this.authRelayService.initiateLogin(providerName);
      res.cookie('oidc_state', state, {
        httpOnly: true,
        secure: process.env.NODE_ENV !== 'development',
        maxAge: 15 * 60 * 1000, // 15 minutes
        path: '/api/auth/oidc/callback',
        sameSite: 'lax',
      });
      res.redirect(302, authorizationUrl);
    } catch (error) {
      res.status(500).send('Login initiation failed.');
    }
  }

  @Get('oidc/callback')
  async oidcCallback(
    @Query('code') code: string,
    @Query('state') stateFromIdp: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const originalState = req.cookies['oidc_state'];
    res.clearCookie('oidc_state', {
      httpOnly: true,
      secure: this.configService.get<string>(ENV) !== 'development',
      path: '/api/auth/oidc/callback',
      sameSite: 'lax',
    });
    if (!originalState || !stateFromIdp || originalState !== stateFromIdp) {
      console.error('OIDC state mismatch or missing state cookie. Potential CSRF.');
      return this.handleRedirect(res, ERROR_REDIRECT, 'unexpected_error', '/');
    }
    if (!code) {
      return this.handleRedirect(res, ERROR_REDIRECT, 'unexpected_error', '/');
    }
    try {
      const authServiceResponse = await this.authRelayService.exchangeCodeForToken(code, stateFromIdp);
      if (authServiceResponse.status === 'success' && authServiceResponse.user_info) {
        const appUser = authServiceResponse.user_info;
        const payload: SessionJwtPayload = {
          sub: appUser.id,
          email: appUser.email,
          roles: appUser.roles && appUser.roles.length > 0 ? appUser.roles : ['User'],
        };
        const sessionToken = await this.kmsJwtService.signKmsJwt(payload);
        res.cookie('session_token', sessionToken, {
          httpOnly: true,
          secure: this.configService.get<string>(ENV) !== 'development',
          maxAge: parseInt(this.configService.get<string>(SESSION_MAX_AGE), 10) * 1000 || 2592000000,
          path: '/',
          sameSite: 'lax',
        });
        return this.handleRedirect(res, LOGIN_SUCCESS_REDIRECT, undefined, '/');
      } else if (authServiceResponse.status === 'email_conflict') {
        return this.handleRedirect(res, ERROR_REDIRECT, 'email_conflict', '/');
      } else {
        return this.handleRedirect(res, ERROR_REDIRECT, 'auth_failed', '/');
      }
    } catch (error) {
      console.error('Error during OIDC callback processing:', error);
      return this.handleRedirect(res, ERROR_REDIRECT, 'unexpected_error', '/');
    }
  }

  @Post('logout')
  async logout(@Res({ passthrough: true }) res: Response) {
    try {
      res.clearCookie('session_token', {
        httpOnly: true,
        secure: this.configService.get<string>(ENV) !== 'development',
        path: '/',
        sameSite: 'lax',
      });
      return { message: 'Logged out successfully' };
    } catch (error) {
      console.error('Error during logout:', error);
      throw new InternalServerErrorException('An error occurred during logout.');
    }
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  async getProfile(@Req() req: Request) {
    const user = req.user as SessionJwtPayload;
    if (!user) {
      throw new UnauthorizedException('No user found in session.');
    }
    return {
      message: 'Successfully authenticated.',
      userId: user.sub,
      email: user.email,
    };
  }

  @Post('link/:providerName')
  @UseGuards(JwtAuthGuard)
  async initiateLinkAccount(
    @Param('providerName') providerName: string,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const user = req.user as SessionJwtPayload;
    if (!user || !user.sub) {
      throw new UnauthorizedException('User not authenticated.');
    }
    const appUserId = user.sub;
    try {
      const { authorizationUrl, state } = await this.authRelayService.initiateAccountLink(
        providerName,
        appUserId,
      );
      res.cookie('oidc_state', state, {
        httpOnly: true,
        secure: this.configService.get<string>('NODE_ENV') !== 'development',
        maxAge: 15 * 60 * 1000, // 15 minutes
        path: '/api/auth/oidc/callback',
        sameSite: 'lax',
      });
      res.redirect(302, authorizationUrl);
    } catch (error) {
      console.error('Error during account linking initiation:', error);
      this.handleRedirect(res, 'FRONTEND_ERROR_REDIRECT_URL', 'link_initiation_failed', '/');
    }
  }
}
