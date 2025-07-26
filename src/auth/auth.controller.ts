import {
	Body,
	Controller,
	HttpCode,
	HttpStatus,
	Post,
	Req,
	Res,
} from "@nestjs/common";
import { AuthService } from "./auth.service";
import {
	type TAuthResponseDto,
	type TSigninUserDto,
	type TSignupUserDto,
	signinUserDto,
	AuthResponseDto,
	SigninUserDto,
	SignupUserDto,
	signupUserDto,
} from "./dto/auth.dto";
import { ZodPipe } from "@/common/pipes/zod/zod.pipe";
import type { Request, Response } from "express";
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";

@ApiTags("Authentication")
@Controller("auth")
export class AuthController {
	constructor(private readonly authService: AuthService) {}

	// Регистрация нового пользователя
	// Используется для создания нового пользователя в системе
	@ApiOperation({
		summary: "Регистрация нового пользователя",
		description: "Создает нового пользователя и возвращает токены доступа.",
	})
	@ApiBody({ type: SignupUserDto })
	@ApiResponse({
		status: HttpStatus.OK,
		type: AuthResponseDto,
		description:
			"После успешной регистрации, сервер отправляет accessToken, а refreshToken сохраняется в cookies.",
	})
	@ApiResponse({
		status: HttpStatus.CONFLICT,
		description: "Пользователь с таким email уже существует.",
	})
	@ApiResponse({
		status: HttpStatus.BAD_REQUEST,
		description: "Некорректные данные для регистрации пользователя.",
	})
	@HttpCode(HttpStatus.OK)
	@Post("signup")
	signup(
		@Body(new ZodPipe(signupUserDto)) dto: TSignupUserDto,
		@Res({ passthrough: true }) res: Response,
	): Promise<TAuthResponseDto> {
		return this.authService.signup(dto, res);
	}

	// Аутентификация пользователя
	// Используется для входа пользователя в систему
	@ApiOperation({
		summary: "Вход пользователя в систему",
		description:
			"Проверяет учетные данные пользователя и возвращает токены доступа.",
	})
	@ApiBody({ type: SigninUserDto })
	@ApiResponse({
		status: HttpStatus.OK,
		type: AuthResponseDto,
		description:
			"После успешной авторизации, сервер отправляет accessToken, а refreshToken сохраняется в cookies.",
	})
	@ApiResponse({
		status: HttpStatus.BAD_REQUEST,
		description: "Некорректные данные для входа пользователя.",
	})
	@HttpCode(HttpStatus.OK)
	@Post("signin")
	signin(
		@Body(new ZodPipe(signinUserDto)) dto: TSigninUserDto,
		@Res({ passthrough: true }) res: Response,
	): Promise<TAuthResponseDto> {
		return this.authService.login(dto, res);
	}

	// Обновление токена доступа
	// Используется для обновления токена доступа пользователя
	@ApiOperation({
		summary: "Обновление токена доступа",
		description:
			"Обновляет токен доступа пользователя. При отправке запроса сервер проверяет наличие refresh токена в куках.",
	})
	@ApiResponse({
		status: HttpStatus.OK,
		type: AuthResponseDto,
		description:
			"После успешной авторизации, сервер отправляет accessToken, а refreshToken сохраняется в cookies.",
	})
	@ApiResponse({
		status: HttpStatus.BAD_REQUEST,
		description: "Некорректные данные для входа пользователя.",
	})
	@HttpCode(HttpStatus.OK)
	@Post("refresh")
	refresh(
		@Res({ passthrough: true }) res: Response,
		@Req() req: Request,
	): Promise<TAuthResponseDto> {
		return this.authService.refresh(res, req);
	}

	// Выход пользователя из системы
	// Используется для завершения сессии пользователя
	@ApiOperation({
		summary: "Выход пользователя из системы",
		description: "Завершает сессию пользователя.",
	})
	@ApiResponse({
		status: HttpStatus.OK,
		description:
			"После успешного выхода, сервер удаляет refreshToken из cookies.",
	})
	@HttpCode(HttpStatus.OK)
	@Post("logout")
	logout(@Res({ passthrough: true }) res: Response): boolean {
		return this.authService.logout(res);
	}
}
