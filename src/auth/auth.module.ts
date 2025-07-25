import { Module } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthController } from "./auth.controller";
import { UsersModule } from "@/users/users.module";
import { JwtModule } from "@nestjs/jwt";
import jwtConfig from "./config/jwt.config";
import { JwtStrategy } from "./strategies/jwt.strategy";

@Module({
	controllers: [AuthController],
	providers: [AuthService, JwtStrategy],
	imports: [UsersModule, JwtModule.registerAsync(jwtConfig.asProvider())],
})
export class AuthModule {}
