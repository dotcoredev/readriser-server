import { AuthGuard } from "@nestjs/passport";

// Декоратор для защиты маршрутов с помощью JWT
export class JwtGuard extends AuthGuard("jwt") {}
