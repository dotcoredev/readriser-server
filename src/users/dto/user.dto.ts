import { createZodDto } from "nestjs-zod";
import z from "zod";

// ============================================================================
// ENUMS & BASIC TYPES
// ============================================================================
export const UserRole = z
	.enum({
		ADMIN: "admin",
		USER: "user",
		MODERATOR: "moderator",
	})
	.describe("Роли пользователей");

export const AccessEnum = z
	.enum({
		ADMIN: "read|write|delete|update",
		USER: "read|write",
		MODERATOR: "read|write|update",
	})
	.describe("Уровень доступа");

// ============================================================================
// CORE SCHEMAS
// ============================================================================
const roleSchema = z
	.object({
		_id: z.string().optional().describe("ID роли"),
		role: UserRole.describe("Роль пользователя"),
		access: AccessEnum.describe("Уровень доступа"),
		//isActive: z.boolean().optional().describe("Активна ли роль"), // опционально, если требуется вернуть на клиент, уберите комментарий
		//description: z.string().optional().describe("Описание роли"), // опционально, если требуется вернуть на клиент, уберите комментарий
	})
	.describe("Схема роли пользователя");

export const userSchema = z
	.object({
		_id: z.string().describe("ID пользователя"),
		email: z.email().min(5).max(100).describe("Email пользователя"),
		firstname: z
			.string()
			.min(2)
			.max(100)
			.optional()
			.describe("Имя пользователя"),
		lastname: z
			.string()
			.min(2)
			.max(100)
			.optional()
			.describe("Фамилия пользователя"),
		login: z.string().min(3).max(50).describe("Логин пользователя"),
		isBan: z
			.boolean()
			.default(false)
			.describe("Заблокирован ли пользователь"),
		isConfirmed: z
			.boolean()
			.default(false)
			.describe("Подтвержден ли пользователь"),
		role: z.union([roleSchema, z.string()]).describe("Роль пользователя"), // может быть ID роли или объект роли
		password: z.string().describe("Пароль пользователя"), // при ответе не передаем пароль клиенту
		createdAt: z.date().optional().describe("Дата создания пользователя"), // опционально
		updatedAt: z.date().optional().describe("Дата обновления пользователя"), // опционально
	})
	.describe("Схема пользователя");

// ============================================================================
// RESPONSE SCHEMAS
// ============================================================================
export const userResponseSchema = userSchema.omit({
	password: true, // исключаем пароль из ответа
	createdAt: true,
	updatedAt: true,
});

// ============================================================================
// TYPE EXPORTS
// ============================================================================
export type TUserSchema = z.infer<typeof userSchema>;
export type TUserResponseSchema = z.infer<typeof userResponseSchema>;
export type TUserRoleSchema = z.infer<typeof UserRole>;

// ============================================================================
// SWAGGER DTOs
// ============================================================================
export class UserSchemaDto extends createZodDto(userResponseSchema) {}
