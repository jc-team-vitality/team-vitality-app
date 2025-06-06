import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';
import { AuthRelayService } from './auth-relay.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { KmsJwtService } from './kms-jwt.service';
import { KmsKeyCacheService } from './kms-key-cache.service';

@Module({
  imports: [
    HttpModule,
    ConfigModule,
    PassportModule.register({ defaultStrategy: 'jwt-session' }),
  ],
  controllers: [AuthController],
  providers: [AuthRelayService, JwtStrategy, JwtAuthGuard, KmsJwtService, KmsKeyCacheService],
  exports: [AuthRelayService],
})
export class AuthModule { }
