import {
	BadRequestException,
	Injectable,
	NotFoundException,
} from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { User } from "./model/user.model";
import { Model } from "mongoose";
import { CreateUserDto } from "@/auth/dto/signup.dto";
import { Role } from "./model/role.model";
import { AccessEnum, RoleEnum } from "./interfaces/role-model.interface";

@Injectable()
export class UsersService {
	constructor(
		@InjectModel(User.name) private readonly userRepository: Model<User>,
		@InjectModel(Role.name) private readonly roleRepository: Model<Role>,
	) {}

	// Получить всех пользователей
	async getAll(): Promise<User[]> {
		return this.userRepository.find().lean().exec();
	}

	// Получить профиль пользователя по email
	// Используется для получения информации о пользователе
	async profile(email: string): Promise<User> {
		// Проверка на существование пользователя по email
		// Если пользователь не найден, выбрасываем исключение
		const findUser = await this.getByEmail(email);
		if (!findUser) throw new BadRequestException("Пользователь не найден");

		// Исключение пароля из ответа
		// Возвращаем пользователя без пароля
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...user } = findUser;

		return user as User;
	}

	// Получить пользователя по ID
	// Используется для получения информации о пользователе
	async getById(id: string): Promise<User> {
		const user = await this.userRepository
			.findById(id)
			.select("-updatedAt")
			.populate("role", "role access -_id")
			.lean()
			.exec();

		return user as User;
	}

	// Получить пользователя по email
	// Используется для аутентификации и регистрации
	// Найденный пользователь возвращется с паролем, не забываем исключать его из ответа
	async getByEmail(email: string): Promise<User> {
		const user = await this.userRepository
			.findOne({ email })
			.select("-updatedAt")
			.populate("role", "role access -_id")
			.lean()
			.exec();

		return user as User;
	}

	// Создать нового пользователя
	// Используется при регистрации
	async create(
		fields: Omit<CreateUserDto, "repeat_password">,
	): Promise<User> {
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
		return savedUser.toJSON<User>();
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
