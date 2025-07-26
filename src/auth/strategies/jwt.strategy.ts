import { PassportStrategy } from "@nestjs/passport";
import { Strategy, ExtractJwt } from "passport-jwt";
import { AuthService } from "../auth.service";
import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { type TJwtPayloadDto } from "../dto/auth.dto";
import { type TUserResponseSchema } from "@/users/dto/user.dto";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
	constructor(
		private readonly authService: AuthService,
		readonly configService: ConfigService,
	) {
		// Конфигурация стратегии JWT
		// Используется для извлечения JWT из заголовка Authorization
		super({
			jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
			ignoreExpiration: false,
			secretOrKey: configService.get<string>("JWT_SECRET") || "",
			algorithms: ["HS256"],
		});
	}

	// Валидация JWT payload
	// Используется для проверки существования пользователя по email
	// Возвращает пользователя, если он существует, или выбрасывает исключение
	// Если пользователь не найден, выбрасывается исключение
	validate(jwtPayload: TJwtPayloadDto): Promise<TUserResponseSchema | null> {
		return this.authService.validate(jwtPayload);
	}
}
