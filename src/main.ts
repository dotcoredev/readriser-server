import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import * as cookieParser from "cookie-parser";
import { swaggerConfig } from "./common/config/swagger.config";

async function bootstrap() {
	const app = await NestFactory.create(AppModule);

	swaggerConfig(app);
	app.enableCors(); // Enable CORS for all origins
	app.use(cookieParser());

	await app.listen(process.env.PORT ?? 3000);
}

void bootstrap();
