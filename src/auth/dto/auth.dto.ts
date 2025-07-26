import { createZodDto } from "nestjs-zod";
import z from "zod";

// ============================================================================
// CORE SCHEMAS
// ============================================================================

// DTO для регистрации пользователя
export const signupUserDto = z
	.object({
		login: z
			.string({
				error: "login обязательное поле",
			})
			.min(3, {
				error: "login должен содержать не менее 3 символов",
			})
			.describe("Логин пользователя"),
		password: z
			.string({
				error: "password обязательное поле",
			})
			.min(6, {
				error: "password должен содержать не менее 6 символов",
			})
			.describe("Пароль пользователя"),
		repeat_password: z
			.string({
				error: "repeat_password обязательное поле",
			})
			.describe("Повторите пароль"),
		email: z
			.email({
				error: "email обязательное поле",
			})
			.describe("Email пользователя"),
	})
	.refine((data) => data.password === data.repeat_password, {
		message: "Пароли не совпадают",
	});

// DTO для входа пользователя
export const signinUserDto = z.object({
	password: z
		.string({
			error: "password обязательное поле",
		})
		.min(6, {
			error: "password должен содержать не менее 6 символов",
		})
		.describe("Пароль пользователя"),

	email: z
		.email({
			error: "email обязательное поле",
		})
		.describe("Email пользователя"),
});

// ============================================================================
// RESPONSE SCHEMAS
// ============================================================================

export const AuthResponseSchema = z.object({
	accessToken: z.string().meta({
		description: "JWT access token",
	}),
});

export const TokensSchema = z.object({
	accessToken: z.string(),
	refreshToken: z.string(),
});

export const JwtPayloadSchema = z.object({
	email: z.email(),
	_id: z.string(),
});

// ============================================================================
// TYPE EXPORTS
// ============================================================================
export type TSignupUserDto = z.infer<typeof signupUserDto>;
export type TSigninUserDto = z.infer<typeof signinUserDto>;
export type TAuthResponseDto = z.infer<typeof AuthResponseSchema>;
export type TTokensDto = z.infer<typeof TokensSchema>;
export type TJwtPayloadDto = z.infer<typeof JwtPayloadSchema>;

// ============================================================================
// SWAGGER DTOs
// ============================================================================
export class AuthResponseDto extends createZodDto(AuthResponseSchema) {}
export class SignupUserDto extends createZodDto(signupUserDto) {}
export class SigninUserDto extends createZodDto(signinUserDto) {}
