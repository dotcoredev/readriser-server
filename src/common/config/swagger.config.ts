import { INestApplication } from "@nestjs/common";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";

export const swaggerConfig = (app: INestApplication) => {
	const config = new DocumentBuilder()
		.setTitle("ReadRiser API")
		.setDescription("API documentation for ReadRiser application")
		.setVersion("1.0.0")
		.setContact(
			"ReadRiser Team",
			"dotcore@gmail.com",
			"https://dotcore.dev",
		)
		.addBearerAuth({
			type: "http",
			scheme: "bearer",
		})
		.build();

	const document = SwaggerModule.createDocument(app, config);
	SwaggerModule.setup("api/docs", app, document, {
		customSiteTitle: "ReadRiser API Docs",
		jsonDocumentUrl: "/api/docs-json",
		customfavIcon: "https://readriser.com/favicon.ico",
	});
};
