import { Controller, Get } from "@nestjs/common";
import { UsersService } from "./users.service";
import { User } from "./model/user.model";
import { Authorization } from "@/auth/decorators/auth.decorator";
import { Authorized } from "@/auth/decorators/authorized.decorator";

@Controller("users")
export class UsersController {
	constructor(private readonly usersService: UsersService) {}

	// Получение всех пользователей
	// Используется для получения списка всех пользователей в системе
	@Get("/")
	async getAllUsers(): Promise<User[]> {
		return this.usersService.getAll();
	}

	// Получение профиля пользователя
	// Используется для получения информации о пользователе по email
	@Authorization()
	@Get("/profile")
	getProfile(@Authorized() user: User): User {
		return user;
	}

	// Создание ролей для пользователей
	// Используется для создания ролей в системе
	//@Post("/create-roles")
	//async createRoles(): Promise<boolean> {
	//	return this.usersService.createRoles();
	//}
}
