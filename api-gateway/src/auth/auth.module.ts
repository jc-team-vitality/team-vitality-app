import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthRelayService } from './auth-relay.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Module({
  imports: [
    HttpModule,
    ConfigModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SESSION_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_SESSION_EXPIRES_IN') || '7d',
        },
      }),
      inject: [ConfigService],
    }),
    PassportModule.register({ defaultStrategy: 'jwt-session' }),
  ],
  controllers: [AuthController],
  providers: [AuthRelayService, JwtStrategy, JwtAuthGuard],
  exports: [AuthRelayService],
})
export class AuthModule {}
