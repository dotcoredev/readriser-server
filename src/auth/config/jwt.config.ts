import { registerAs } from "@nestjs/config";
import { JwtModuleOptions } from "@nestjs/jwt";

export default registerAs<JwtModuleOptions>("jwt", () => ({
	secret: process.env.JWT_SECRET,
	signOptions: {
		algorithm: "HS256",
	},
	verifyOptions: {
		algorithms: ["HS256"],
		ignoreExpiration: false, // Проверка срока действия токена
	},
}));
