import { Controller, Get, Param, Res, Req, Query, UnauthorizedException, Post, InternalServerErrorException } from '@nestjs/common';
import { Response, Request } from 'express';
import { AuthRelayService } from './auth-relay.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authRelayService: AuthRelayService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

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
      secure: this.configService.get<string>('NODE_ENV') !== 'development',
      path: '/api/auth/oidc/callback',
      sameSite: 'lax',
    });
    if (!originalState || !stateFromIdp || originalState !== stateFromIdp) {
      console.error('OIDC state mismatch or missing state cookie. Potential CSRF.');
      // Redirect to error URI with code=state_mismatch
      const errorUri = this.configService.get<string>('FRONTEND_ERROR_REDIRECT_URL', '/login-error');
      const url = new URL(errorUri, 'http://dummy-base');
      url.searchParams.set('code', 'state_mismatch');
      return res.redirect(url.pathname + url.search);
    }
    if (!code) {
      // Redirect to error URI with code=missing_code
      const errorUri = this.configService.get<string>('FRONTEND_ERROR_REDIRECT_URL', '/login-error');
      const url = new URL(errorUri, 'http://dummy-base');
      url.searchParams.set('code', 'missing_code');
      return res.redirect(url.pathname + url.search);
    }
    try {
      const authServiceResponse = await this.authRelayService.exchangeCodeForToken(code, stateFromIdp);
      if (authServiceResponse.status === 'success' && authServiceResponse.user_info) {
        const appUser = authServiceResponse.user_info;
        const payload = { sub: appUser.id, email: appUser.email };
        const sessionToken = await this.jwtService.signAsync(payload);
        res.cookie('session_token', sessionToken, {
          httpOnly: true,
          secure: this.configService.get<string>('NODE_ENV') !== 'development',
          maxAge: parseInt(this.configService.get<string>('JWT_SESSION_MAX_AGE_SECONDS', '2592000')) * 1000,
          path: '/',
          sameSite: 'lax',
        });
        return res.redirect(this.configService.get<string>('FRONTEND_LOGIN_SUCCESS_REDIRECT_URL', '/dashboard'));
      } else if (authServiceResponse.status === 'email_conflict') {
        // Redirect to error URI with code=email_conflict
        const errorUri = this.configService.get<string>('FRONTEND_ERROR_REDIRECT_URL', '/login-error');
        const url = new URL(errorUri, 'http://dummy-base');
        url.searchParams.set('code', 'email_conflict');
        return res.redirect(url.pathname + url.search);
      } else {
        // Redirect to error URI with code=auth_failed
        const errorUri = this.configService.get<string>('FRONTEND_ERROR_REDIRECT_URL', '/login-error');
        const url = new URL(errorUri, 'http://dummy-base');
        url.searchParams.set('code', 'auth_failed');
        return res.redirect(url.pathname + url.search);
      }
    } catch (error) {
      console.error('Error during OIDC callback processing:', error);
      // Redirect to error URI with code=callback_processing_failed
      const errorUri = this.configService.get<string>('FRONTEND_ERROR_REDIRECT_URL', '/login-error');
      const url = new URL(errorUri, 'http://dummy-base');
      url.searchParams.set('code', 'callback_processing_failed');
      return res.redirect(url.pathname + url.search);
    }
  }

  @Post('logout')
  async logout(@Res({ passthrough: true }) res: Response) {
    try {
      res.clearCookie('session_token', {
        httpOnly: true,
        secure: this.configService.get<string>('NODE_ENV') !== 'development',
        path: '/',
        sameSite: 'lax',
      });
      return { message: 'Logged out successfully' };
    } catch (error) {
      console.error('Error during logout:', error);
      throw new InternalServerErrorException('An error occurred during logout.');
    }
  }
}
