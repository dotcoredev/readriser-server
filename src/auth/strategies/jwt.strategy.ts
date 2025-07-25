import { PassportStrategy } from "@nestjs/passport";
import { Strategy, ExtractJwt } from "passport-jwt";
import { AuthService } from "../auth.service";
import { type JwtPayload } from "../interfaces/jwt-payload.interface";
import { Injectable } from "@nestjs/common";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
	constructor(private readonly authService: AuthService) {
		super({
			jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
			ignoreExpiration: false,
			secretOrKey: process.env.JWT_SECRET || "",
			algorithms: ["HS256"],
		});
	}

	validate(jwtPayload: JwtPayload) {
		// Валидация JWT payload
		// Используется для проверки существования пользователя по email
		// Возвращает пользователя, если он существует, или выбрасывает исключение
		// Если пользователь не найден, выбрасывается исключение
		return this.authService.validate(jwtPayload);
	}
}
