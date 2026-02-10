import { NestFactory, Reflector } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import { JwtAuthGuard } from './common/guards/jwt-auth.guard';
import { NestExpressApplication } from '@nestjs/platform-express';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    logger: false,
  });
  const config = new ConfigService();

  app.useGlobalGuards(new JwtAuthGuard(app.get(Reflector)));

  app.enableCors({
    origin: true,
    methods: 'GET,POST,PUT,PATCH,HEAD,DELETE,OPTIONS',
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  const swaggerDoc = new DocumentBuilder()
    .setTitle('Test API')
    .setDescription('Demo APIs')
    .setVersion('1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
      'jwt',
    )
    .build();

  const document = SwaggerModule.createDocument(app, swaggerDoc);
  SwaggerModule.setup('docs', app, document);

  await app.listen(config.get('PORT'));
  console.log(`Api server runing on ${process.env.PORT}`);
}
bootstrap().catch((err) => {
  console.error(err);
  process.exit(1);
});
