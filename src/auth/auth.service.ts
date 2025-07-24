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
import { UserDocument } from "@/users/model/user.model";
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

	async signup(dto: CreateUserDto, res: Response): Promise<ISignupResponse> {
		const findedUser = await this.usersService.getByEmail(dto.email);

		if (findedUser)
			throw new ConflictException(
				"Пользователь с таким email уже существует",
			);
		const createdUser = await this.usersService.create(dto);
		if (!createdUser)
			throw new BadRequestException("Ошибка при создании пользователя");

		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...user } = createdUser.toJSON();
		const payload: JwtPayload = {
			email: user.email,
			_id: user._id.toString(),
		};
		const { access_token } = this.generateTokens(payload, res);

		return {
			access_token,
		};
	}

	async login(dto: SigninUserDto, res: Response): Promise<ISignupResponse> {
		const signinUser = await this.signin(dto);

		const payload: JwtPayload = {
			email: signinUser.email,
			_id: signinUser._id.toString(),
		};
		const { access_token } = this.generateTokens(payload, res);

		return {
			access_token,
		};
	}

	async refresh(res: Response, req: Request): Promise<ISignupResponse> {
		try {
			// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
			const refreshToken: string = req.cookies["refresh_token"];
			if (!refreshToken)
				throw new UnauthorizedException("Отсутствует refresh токен");

			const parseToken: JwtPayload =
				await this.jwtService.verifyAsync(refreshToken);

			if (!parseToken) {
				throw new NotFoundException("Неверный refresh токен");
			}

			const user = await this.usersService.getById(parseToken._id);
			if (!user) {
				throw new NotFoundException("Пользователь не найден");
			}

			const payload: JwtPayload = {
				email: user.email,
				_id: user._id.toString(),
			};

			const { access_token } = this.generateTokens(payload, res);
			return {
				access_token,
			};
		} catch (error: unknown) {
			const errorMessage =
				error instanceof Error ? error.message : "Unknown error";
			throw new BadRequestException({
				message: errorMessage,
			});
		}
	}

	logout(res: Response): boolean {
		this.setCookies(res, "");
		return true;
	}

	async signin(dto: SigninUserDto): Promise<UserDocument> {
		const findedUser: UserDocument = await this.usersService.getByEmail(
			dto.email,
		);

		if (!findedUser)
			throw new BadRequestException(
				"Пользователь с таким email не найден",
			);

		const isPasswordValid = await this.comparePasswords(
			dto.password,
			findedUser.password,
		);

		if (!isPasswordValid) throw new BadRequestException("Неверный пароль");

		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...user } = findedUser;

		return user as UserDocument;
	}

	setCookies(res: Response, value: string): boolean {
		const expiresEnv =
			this.configService.get<string>("JWT_REFRESH_EXPIRATION") || "30d";
		const expiresMs = ms(expiresEnv as ms.StringValue);
		const expires = new Date(Date.now() + expiresMs);

		res.cookie("refresh_token", value, {
			httpOnly: true,
			sameSite: "strict",
			expires: expires,
			secure: process.env.NODE_ENV === "production", // Use secure cookies in production
		});
		return true;
	}

	generateTokens(payload: JwtPayload, res: Response): ITokens {
		const access_token = this.jwtService.sign(payload, {
			algorithm: "HS256",
			expiresIn: this.configService.get<string>("JWT_EXPIRATION") || "1h",
		});

		const refresh_token = this.jwtService.sign(payload, {
			algorithm: "HS256",
			expiresIn:
				this.configService.get<string>("JWT_REFRESH_EXPIRATION") ||
				"30d",
		});

		this.setCookies(res, refresh_token);

		return { access_token, refresh_token };
	}

	comparePasswords(
		password: string,
		hashedPassword: string,
	): Promise<boolean> {
		return bcrypt.compare(password, hashedPassword);
	}
}
