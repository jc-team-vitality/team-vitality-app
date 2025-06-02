import { Module } from '@nestjs/common';
import { IdpConfigsController } from './idp-configs.controller';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [AuthModule],
  controllers: [IdpConfigsController],
})
export class AdminModule {}
