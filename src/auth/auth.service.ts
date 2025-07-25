import {
	BadRequestException,
	ConflictException,
	Injectable,
	NotFoundException,
	UnauthorizedException,
} from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { UsersService } from "src/users/users.service";
import { CreateUserDto } from "./dto/signup.dto";
import { ISignupResponse, ITokens } from "./interfaces/signup.interface";
import { SigninUserDto } from "./dto/signin.dto";
import * as bcrypt from "bcrypt";
import type { Request, Response } from "express";
import { User } from "@/users/model/user.model";
import { ConfigService } from "@nestjs/config";
import * as ms from "ms";
import { JwtPayload } from "./interfaces/jwt-payload.interface";

@Injectable()
export class AuthService {
	constructor(
		private readonly usersService: UsersService,
		private readonly jwtService: JwtService,
		private readonly configService: ConfigService,
	) {}

	// Регистрация нового пользователя
	// Используется для создания нового пользователя в системе
	async signup(dto: CreateUserDto, res: Response): Promise<ISignupResponse> {
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { repeat_password, ...userDtoFields } = dto;

		// Проверка на существование пользователя
		const findedUser: User = await this.usersService.getByEmail(
			userDtoFields.email,
		);

		if (findedUser)
			throw new ConflictException(
				"Пользователь с таким email уже существует",
			);

		// Создание нового пользователя
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...user } =
			await this.usersService.create(userDtoFields);

		const payload: JwtPayload = {
			email: user.email,
			_id: user._id,
		};

		// Генерация токенов и установка refresh_token в куки
		// Возвращаем access_token в ответе
		const { access_token } = this.generateTokens(payload, res);

		return {
			access_token,
		};
	}

	// Аутентификация пользователя
	// Используется для входа пользователя в систему
	async login(dto: SigninUserDto, res: Response): Promise<ISignupResponse> {
		// Проверка на существование пользователя
		// Если пользователь не найден, выбрасываем исключение внитри метода signin
		const checkUser: User = await this.signin(dto);

		// Создание JWT payload
		// Используется для создания токенов
		const payload: JwtPayload = {
			email: checkUser.email,
			_id: checkUser._id.toString(),
		};

		// Генерация токенов и установка refresh_token в куки
		// Возвращаем access_token в ответе
		const { access_token } = this.generateTokens(payload, res);

		return {
			access_token,
		};
	}

	// Обновление токена доступа
	// Используется для обновления токена доступа пользователя
	async refresh(res: Response, req: Request): Promise<ISignupResponse> {
		try {
			// Получение refresh токена из куки
			// Если токен отсутствует, выбрасываем исключение
			// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
			const getRefreshTokenFromCookies: string =
				req.cookies["refresh_token"];
			if (!getRefreshTokenFromCookies)
				throw new UnauthorizedException("Отсутствует refresh токен");

			const refreshToken: string =
				getRefreshTokenFromCookies.split(" ")[1];
			// Проверка и декодирование refresh токена
			// Если токен недействителен, выбрасываем исключение
			const parseToken: JwtPayload =
				await this.jwtService.verifyAsync(refreshToken);

			if (!parseToken) {
				throw new NotFoundException("Неверный refresh токен");
			}

			// Получение пользователя по ID из токена
			// Если пользователь не найден, выбрасываем исключение
			const user: User = await this.usersService.getById(parseToken._id);
			if (!user) {
				throw new NotFoundException("Пользователь не найден");
			}

			// Создание JWT payload
			// Используется для создания токенов
			const payload: JwtPayload = {
				email: user.email,
				_id: user._id,
			};
			const { access_token } = this.generateTokens(payload, res);

			return {
				access_token,
			};
		} catch (error: unknown) {
			// Обработка ошибок
			// Если произошла ошибка при проверке токена или получении пользователя, выбрасываем исключение
			const errorMessage =
				error instanceof Error ? error.message : "Unknown error";
			throw new BadRequestException({
				message: errorMessage,
			});
		}
	}

	// Выход пользователя из системы
	// Используется для завершения сессии пользователя
	// Удаление refresh токена из куки
	logout(res: Response): boolean {
		this.setCookies(res, "");
		return true;
	}

	// Валидация JWT payload
	// Используется для проверки существования пользователя по email
	async validate({ email }: JwtPayload): Promise<User> {
		const findedUser: User = await this.usersService.getByEmail(email);

		if (!findedUser)
			throw new BadRequestException(
				"Пользователь с таким email не найден",
			);

		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...user } = findedUser;

		// Возвращаем пользователя без пароля
		return user as User;
	}

	// Аутентификация пользователя по email и паролю
	// Используется для входа пользователя в систему
	async signin(dto: SigninUserDto): Promise<User> {
		const findedUser: User = await this.usersService.getByEmail(dto.email);

		// Проверка на существование пользователя
		// Если пользователь не найден, выбрасываем исключение
		if (!findedUser)
			throw new BadRequestException(
				"Пользователь с таким email не найден",
			);

		// Проверка пароля
		// Если пароль неверный, выбрасываем исключение
		const isPasswordValid = await this.comparePasswords(
			dto.password,
			findedUser.password,
		);
		if (!isPasswordValid) throw new BadRequestException("Неверный пароль");

		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...user } = findedUser;

		// Возвращаем пользователя без пароля
		return user as User;
	}

	// Установка refresh токена в куки
	// Используется для сохранения refresh токена в куки браузера
	setCookies(res: Response, value: string): boolean {
		// Преобразование строки в миллисекунды
		// Используется для установки времени жизни куки
		const expiresEnv =
			this.configService.get<string>("JWT_REFRESH_EXPIRATION") || "30d";
		const expiresMs = ms(expiresEnv as ms.StringValue);
		const expires = new Date(Date.now() + expiresMs);

		res.cookie("refresh_token", value, {
			httpOnly: true, // Запретить доступ к куки через JavaScript
			sameSite: "lax", // Использовать lax для улучшения безопасности
			expires: expires, // Установить время жизни куки
			secure: process.env.NODE_ENV === "production", // Использовать secure cookies в продакшене
		});
		return true;
	}

	// Генерация токенов
	// Используется для создания access и refresh токенов
	generateTokens(payload: JwtPayload, res: Response): ITokens {
		// Генерация access токена
		// Используется для доступа к защищенным ресурсам
		const generateAccessToken = this.jwtService.sign(payload, {
			algorithm: "HS256",
			expiresIn: this.configService.get<string>("JWT_EXPIRATION") || "1h",
		});
		const access_token = `Bearer ${generateAccessToken}`;

		// Генерация refresh токена
		// Используется для обновления access токена
		const generateRefreshToken = this.jwtService.sign(payload, {
			algorithm: "HS256",
			expiresIn:
				this.configService.get<string>("JWT_REFRESH_EXPIRATION") ||
				"30d",
		});
		const refresh_token = `Bearer ${generateRefreshToken}`;

		// Установка refresh токена в куки
		this.setCookies(res, refresh_token);

		return { access_token, refresh_token };
	}

	// Сравнение паролей
	// Используется для проверки правильности введенного пароля
	comparePasswords(
		password: string,
		hashedPassword: string,
	): Promise<boolean> {
		return bcrypt.compare(password, hashedPassword);
	}
}
