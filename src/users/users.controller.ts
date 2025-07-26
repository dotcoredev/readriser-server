import { Controller, Get, HttpCode, HttpStatus } from "@nestjs/common";
import { UsersService } from "./users.service";
import { Authorization } from "@/auth/decorators/auth.decorator";
import { Authorized } from "@/auth/decorators/authorized.decorator";
import {
	TUserResponseSchema,
	TUserSchema,
	UserSchemaDto,
} from "./dto/user.dto";
import { ApiBearerAuth, ApiOperation, ApiResponse } from "@nestjs/swagger";

@Controller("users")
export class UsersController {
	constructor(private readonly usersService: UsersService) {}

	// Получение всех пользователей
	// Используется для получения списка всех пользователей в системе
	@ApiOperation({
		summary: "Получение всех пользователей",
		description: "Возвращает информацию о всех пользователях.",
	})
	@ApiResponse({
		status: HttpStatus.OK,
		type: UserSchemaDto,
		isArray: true,
		description: "Возвращает список всех пользователей.",
	})
	@ApiResponse({
		status: HttpStatus.BAD_REQUEST,
		description: "Некорректные данные для запроса пользователей.",
	})
	@HttpCode(HttpStatus.OK)
	@Get("/")
	async getAllUsers(): Promise<TUserResponseSchema[]> {
		return this.usersService.getAll();
	}

	// Получение профиля пользователя
	// Используется для получения информации о пользователе по email
	@ApiOperation({
		summary: "Получение профиля пользователя",
		description: "Возвращает информацию о пользователе.",
	})
	@ApiBearerAuth()
	@ApiResponse({
		status: HttpStatus.OK,
		type: UserSchemaDto,
		description: "Возвращает информацию о пользователе.",
	})
	@ApiResponse({
		status: HttpStatus.UNAUTHORIZED,
		description: "Unauthorized",
	})
	@ApiResponse({
		status: HttpStatus.BAD_REQUEST,
		description: "Некорректные данные для входа пользователя.",
	})
	@HttpCode(HttpStatus.OK)
	@Authorization()
	@Get("/profile")
	getProfile(@Authorized() user: TUserSchema): TUserResponseSchema {
		return user;
	}

	// Создание ролей для пользователей
	// Используется для создания ролей в системе
	//@Post("/create-roles")
	//async createRoles(): Promise<boolean> {
	//	return this.usersService.createRoles();
	//}
}
