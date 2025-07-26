import {
	BadRequestException,
	ConflictException,
	Injectable,
	NotFoundException,
	UnauthorizedException,
} from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { UsersService } from "src/users/users.service";
import type {
	TAuthResponseDto,
	TTokensDto,
	TJwtPayloadDto,
	TSigninUserDto,
	TSignupUserDto,
} from "./dto/auth.dto";
import * as bcrypt from "bcrypt";
import type { Request, Response } from "express";
import { ConfigService } from "@nestjs/config";
import * as ms from "ms";
import { JwtPayload } from "./interfaces/jwt-payload.interface";
import {
	TUserResponseSchema,
	TUserSchema,
	userResponseSchema,
} from "@/users/dto/user.dto";

@Injectable()
export class AuthService {
	constructor(
		private readonly usersService: UsersService,
		private readonly jwtService: JwtService,
		private readonly configService: ConfigService,
	) {}

	// Регистрация нового пользователя
	// Используется для создания нового пользователя в системе
	async signup(
		dto: TSignupUserDto,
		res: Response,
	): Promise<TAuthResponseDto> {
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { repeat_password, ...userDtoFields } = dto;

		// Проверка на существование пользователя
		const findedUser: TUserSchema | null =
			await this.usersService.getByEmail(userDtoFields.email);

		if (findedUser)
			throw new ConflictException(
				"Пользователь с таким email уже существует",
			);

		// Создание нового пользователя
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...user } =
			await this.usersService.create(userDtoFields);

		const payload: TJwtPayloadDto = {
			email: user.email,
			_id: user._id,
		};

		// Генерация токенов и установка refresh_token в куки
		// Возвращаем access_token в ответе
		const { accessToken } = this.generateTokens(payload, res);

		return {
			accessToken,
		};
	}

	// Аутентификация пользователя
	// Используется для входа пользователя в систему
	async login(dto: TSigninUserDto, res: Response): Promise<TAuthResponseDto> {
		// Проверка на существование пользователя
		// Если пользователь не найден, выбрасываем исключение внитри метода signin
		const checkUser: TUserResponseSchema = await this.signin(dto);

		// Создание JWT payload
		// Используется для создания токенов
		const payload: TJwtPayloadDto = {
			email: checkUser.email,
			_id: checkUser._id,
		};

		// Генерация токенов и установка refresh_token в куки
		// Возвращаем access_token в ответе
		const { accessToken } = this.generateTokens(payload, res);

		return {
			accessToken,
		};
	}

	// Обновление токена доступа
	// Используется для обновления токена доступа пользователя
	async refresh(res: Response, req: Request): Promise<TAuthResponseDto> {
		try {
			// Получение refresh токена из куки
			// Если токен отсутствует, выбрасываем исключение
			// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
			const getRefreshTokenFromCookies: string =
				req.cookies["refreshToken"];
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
			const user: TUserSchema | null = await this.usersService.getById(
				parseToken._id,
			);
			if (!user) {
				throw new NotFoundException("Пользователь не найден");
			}

			// Создание JWT payload
			// Используется для создания токенов
			const payload: TJwtPayloadDto = {
				email: user.email,
				_id: user._id,
			};
			const { accessToken } = this.generateTokens(payload, res);

			return {
				accessToken,
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
	async validate({
		email,
	}: TJwtPayloadDto): Promise<TUserResponseSchema | null> {
		const findedUser: TUserSchema | null =
			await this.usersService.getByEmail(email);

		if (!findedUser)
			throw new BadRequestException(
				"Пользователь с таким email не найден",
			);

		// Преобразование пользователя в DTO
		// Возвращаем пользователя без пароля
		// Используется для отправки данных клиенту
		const userResponse: TUserResponseSchema = this.parseUserDto(findedUser);

		return userResponse;
	}

	// Аутентификация пользователя по email и паролю
	// Используется для входа пользователя в систему
	async signin(dto: TSigninUserDto): Promise<TUserResponseSchema> {
		const findedUser: TUserSchema | null =
			await this.usersService.getByEmail(dto.email);

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

		// Преобразование пользователя в DTO
		// Возвращаем пользователя без пароля
		// Используется для отправки данных клиенту
		const userResponse: TUserResponseSchema = this.parseUserDto(findedUser);

		// Возвращаем пользователя без пароля
		return userResponse;
	}

	// Преобразование пользователя в DTO
	// Используется для отправки данных клиенту
	parseUserDto(user: TUserSchema): TUserResponseSchema {
		const parseUser: TUserResponseSchema = userResponseSchema.parse({
			...user,
			_id: user._id.toString(),
		});
		return parseUser;
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

		res.cookie("refreshToken", value, {
			httpOnly: true, // Запретить доступ к куки через JavaScript
			sameSite: "lax", // Использовать lax для улучшения безопасности
			expires: expires, // Установить время жизни куки
			secure: process.env.NODE_ENV === "production", // Использовать secure cookies в продакшене
		});
		return true;
	}

	// Генерация токенов
	// Используется для создания access и refresh токенов
	generateTokens(payload: TJwtPayloadDto, res: Response): TTokensDto {
		// Генерация access токена
		// Используется для доступа к защищенным ресурсам
		const generateAccessToken = this.jwtService.sign(payload, {
			expiresIn: this.configService.get<string>("JWT_EXPIRATION") || "1h",
		});
		const accessToken = `Bearer ${generateAccessToken}`;

		// Генерация refresh токена
		// Используется для обновления access токена
		const generateRefreshToken = this.jwtService.sign(payload, {
			expiresIn:
				this.configService.get<string>("JWT_REFRESH_EXPIRATION") ||
				"30d",
		});
		const refreshToken = `Bearer ${generateRefreshToken}`;

		// Установка refresh токена в куки
		this.setCookies(res, refreshToken);

		return { accessToken, refreshToken };
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
