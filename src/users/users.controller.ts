import { Controller, Get, Req, UseGuards } from "@nestjs/common";
import { UsersService } from "./users.service";
import { User } from "./model/user.model";
import { AuthGuard } from "@nestjs/passport";
import { Request } from "express";

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
	@UseGuards(AuthGuard("jwt"))
	@Get("/profile")
	getProfile(@Req() req: Request): User {
		return req.user as User;
	}

	// Создание ролей для пользователей
	// Используется для создания ролей в системе
	//@Post("/create-roles")
	//async createRoles(): Promise<boolean> {
	//	return this.usersService.createRoles();
	//}
}
