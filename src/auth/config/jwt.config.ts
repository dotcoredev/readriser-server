import { registerAs } from "@nestjs/config";
import { JwtModuleOptions } from "@nestjs/jwt";

export default registerAs(
	"jwt",
	(): JwtModuleOptions => ({
		secret: process.env.JWT_SECRET,
		signOptions: {
			algorithm: "HS256",
		},
		verifyOptions: {
			algorithms: ["HS256"],
			ignoreExpiration: false, // Set to true if you want to ignore expiration
		},
	}),
);
