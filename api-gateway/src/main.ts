import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // Use the provided PORT environment variable or default to 3001
  const port = process.env.PORT || 3001;
  await app.listen(port);
  console.log(`Application listening on port ${port}`);
}
bootstrap();
