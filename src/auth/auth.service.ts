import {
	BadRequestException,
	ConflictException,
	Injectable,
} from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { UsersService } from "src/users/users.service";
import { CreateUserDto } from "./dto/signup.dto";
import { ISignupResponse, ITokens } from "./interfaces/signup.interface";
import { SigninUserDto } from "./dto/signin.dto";
import * as bcrypt from "bcrypt";
import type { Response } from "express";
import { UserDocument } from "@/users/model/user.model";
import { ConfigService } from "@nestjs/config";
import * as ms from "ms";

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
		const { access_token, refresh_token } = this.generateTokens(user);
		this.setCookies(res, refresh_token);
		return {
			access_token,
		};
	}

	async login(dto: SigninUserDto, res: Response): Promise<ISignupResponse> {
		const signinUser = await this.signin(dto);

		const { access_token, refresh_token } = this.generateTokens(signinUser);
		this.setCookies(res, refresh_token);

		return {
			access_token,
		};
	}

	logout(res: Response): boolean {
		this.setCookies(res, "");
		return true;
	}

	async signin(dto: SigninUserDto): Promise<Partial<UserDocument>> {
		const findedUser = await this.usersService.getByEmail(dto.email);

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

		return user;
	}

	setCookies(res: Response, value: string): boolean {
		const expiresEnv =
			this.configService.get<string>("JWT_REFRESH_EXPIRATION") || "30d";
		// eslint-disable-next-line @typescript-eslint/no-unsafe-call
		const expiresMs = ms(expiresEnv as ms.StringValue) as number;
		const expires = new Date(Date.now() + expiresMs);

		res.cookie("refresh_token", value, {
			httpOnly: true,
			sameSite: "strict",
			expires: expires,
			secure: process.env.NODE_ENV === "production", // Use secure cookies in production
		});
		return true;
	}

	generateTokens(user: Partial<UserDocument>): ITokens {
		const access_token = this.jwtService.sign(
			{
				email: user?.email,
				_id: user?._id,
			},
			{
				algorithm: "HS256",
				expiresIn:
					this.configService.get<string>("JWT_EXPIRATION") || "1h",
			},
		);
		const refresh_token = this.jwtService.sign(
			{
				email: user?.email,
				_id: user?._id,
			},
			{
				algorithm: "HS256",
				expiresIn:
					this.configService.get<string>("JWT_REFRESH_EXPIRATION") ||
					"30d",
			},
		);

		return { access_token, refresh_token };
	}

	comparePasswords(
		password: string,
		hashedPassword: string,
	): Promise<boolean> {
		return bcrypt.compare(password, hashedPassword);
	}
}
