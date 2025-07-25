import { User } from "@/users/model/user.model";
import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { Request } from "express";

// Декоратор для получения авторизованного пользователя
// Используется для извлечения данных пользователя из запроса
// Если указан параметр data, возвращает только это поле пользователя
// Иначе возвращает весь объект пользователя
// Пример использования: @Authorized("_id") userId: string
// Или просто @Authorized() для получения всего объекта пользователя
export const Authorized = createParamDecorator(
	(data: keyof User, ctx: ExecutionContext) => {
		// Извлекает объект запроса из контекста
		const req: Request = ctx.switchToHttp().getRequest();
		const user = req.user as User;
		return data ? user[data] : user;
	},
);
