import { Injectable, NotFoundException } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { User } from "./model/user.model";
import { Model } from "mongoose";
import { Role } from "./model/role.model";
import { AccessEnum, RoleEnum } from "./interfaces/role-model.interface";
import { type TUserResponseSchema, type TUserSchema } from "./dto/user.dto";
import type { TSignupUserDto } from "@/auth/dto/auth.dto";

@Injectable()
export class UsersService {
	constructor(
		@InjectModel(User.name) private readonly userRepository: Model<User>,
		@InjectModel(Role.name) private readonly roleRepository: Model<Role>,
	) {}

	// Получить всех пользователей
	async getAll(): Promise<TUserResponseSchema[]> {
		return this.userRepository
			.find()
			.select("-password -updatedAt")
			.lean()
			.exec();
	}

	// Получить пользователя по ID
	// Используется для получения информации о пользователе
	// Метод не используется напрямую для отправки данных клиенту
	async getById(id: string): Promise<TUserSchema | null> {
		return this.userRepository
			.findById(id)
			.populate("role", "-_id")
			.lean()
			.exec();
	}

	// Получить пользователя по email
	// Используется для аутентификации и регистрации
	// Найденный пользователь возвращется с паролем, не забываем исключать его из ответа
	// Метод не используется напрямую для отправки данных клиенту
	async getByEmail(email: string): Promise<TUserSchema | null> {
		return this.userRepository
			.findOne({ email })
			.populate("role", "-_id")
			.lean()
			.exec();
	}

	// Создать нового пользователя
	// Используется при регистрации
	async create(
		fields: Omit<TSignupUserDto, "repeat_password">,
	): Promise<TUserSchema> {
		// Проверка на существование роли по умолчанию
		// Если роль не найдена, выбрасываем исключение
		const getDefaultRole = await this.roleRepository
			.findOne({ role: RoleEnum.USER })
			.lean()
			.exec();

		if (!getDefaultRole) {
			throw new NotFoundException("Роль по умолчанию не найдена");
		}

		// Объединение полей с ролью по умолчанию
		const userFields = Object.assign(fields, {
			role: getDefaultRole._id,
		});
		// Создание нового пользователя
		const newUser = new this.userRepository(userFields);
		const savedUser = await newUser.save();
		return savedUser.toJSON<TUserSchema>();
	}

	// Создать роли по умолчанию
	// Используется при инициализации приложения
	async createRoles(): Promise<boolean> {
		await this.roleRepository.create({
			role: RoleEnum.ADMIN,
			access: AccessEnum.ADMIN,
			description: "Administrator with full access",
		});

		await this.roleRepository.create({
			role: RoleEnum.MODERATOR,
			access: AccessEnum.MODERATOR,
			description: "Moderator with elevated privileges",
		});

		await this.roleRepository.create({
			role: RoleEnum.USER,
			access: AccessEnum.USER,
			description: "Regular user with limited access",
		});

		return true;
	}
}
