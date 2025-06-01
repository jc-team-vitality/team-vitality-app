import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser()); // Enable cookie-parser globally
  // Prefix all routes with /api
  app.setGlobalPrefix('api');
  // Use the provided PORT environment variable or default to 3001
  const port = process.env.PORT || 3001;
  await app.listen(port);
  console.log(`Application listening on port ${port}`);
}
bootstrap();
