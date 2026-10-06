import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import { JwtAuthGuard } from './auth/jwt-auth.guard';
import { TransformInterceptor } from './core/transform.interceptor';
import cookieParser from 'cookie-parser';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    // Giữ nguyên nội dung gốc để xác thực HMAC của webhook Haravan.
    // (X-Haravan-Hmacsha256 = base64(HMAC_SHA256(raw_body, client_secret)))
    rawBody: true,
  });

  // Nạp cấu hình từ biến môi trường.
  const configService = app.get(ConfigService);

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
    }),
  );

  // Truyền metadata cho bộ bảo vệ toàn cục.
  const reflector = app.get('Reflector');
  app.useGlobalGuards(new JwtAuthGuard(reflector));
  app.useGlobalInterceptors(new TransformInterceptor(reflector));

  // Cấu hình bộ phân tích cookie.
  app.use(cookieParser());

  // Cấu hình CORS.
  app.enableCors({
    origin: true,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    allowedHeaders: 'Content-Type, Accept, Authorization',
    credentials: true,
  });

  // Cấu hình phiên bản API.
  app.setGlobalPrefix('api');
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: ['1', '2'],
  });
  app.useStaticAssets(join(__dirname, '..', 'public')); // Tệp JavaScript, CSS và hình ảnh.
  app.setBaseViewsDir(join(__dirname, '..', 'views')); // Thư mục giao diện.
  app.setViewEngine('ejs');

  // Cấu hình Swagger.
  const config = new DocumentBuilder()
    .setTitle('API documentation')
    .setDescription('Restful API')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'Bearer',
        bearerFormat: 'JWT',
        in: 'header',
      },
      'token',
    )
    .addSecurityRequirements('token')
    .build();

  // Khởi động máy chủ tại cổng ${PORT}.
  await app.listen(configService.get<string>('PORT'), () => {
    console.log(
      `Server is running at http://localhost:${configService.get<string>(
        'PORT',
      )}`,
    );
  });
}
bootstrap();
