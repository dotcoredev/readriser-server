import { applyDecorators, UseGuards } from "@nestjs/common";
import { JwtGuard } from "../guards/jwt.guard";

// Декоратор для защиты маршрутов с помощью JWT
export function Authorization() {
	// Применяет JwtGuard к маршруту, защищая его от неавторизованного доступа
	return applyDecorators(UseGuards(JwtGuard));
}
