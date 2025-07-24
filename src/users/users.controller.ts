import { Controller, Get, Query } from "@nestjs/common";
import { UsersService } from "./users.service";
import { User } from "./model/user.model";
import { ZodPipe } from "@/common/pipes/zod/zod.pipe";
import { ProfileDto, profileDto } from "./dto/profile.dto";

@Controller("users")
export class UsersController {
	constructor(private readonly usersService: UsersService) {}

	// Получение всех пользователей
	// Используется для получения списка всех пользователей в системе
	@Get("/")
	async getAllUsers() {
		return this.usersService.getAll();
	}

	// Получение профиля пользователя
	// Используется для получения информации о пользователе по email
	@Get("/profile")
	async getProfile(
		@Query(new ZodPipe(profileDto)) dto: ProfileDto,
	): Promise<User> {
		return this.usersService.profile(dto.email);
	}

	// Создание ролей для пользователей
	// Используется для создания ролей в системе
	//@Post("/create-roles")
	//async createRoles(): Promise<boolean> {
	//	return this.usersService.createRoles();
	//}
}
