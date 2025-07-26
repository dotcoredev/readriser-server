import { createZodDto } from "nestjs-zod";
import z from "zod";

// ============================================================================
// ENUMS & BASIC TYPES
// ============================================================================
export const UserRole = z.enum({
	ADMIN: "admin",
	USER: "user",
	MODERATOR: "moderator",
});

export const AccessEnum = z.enum({
	ADMIN: "read|write|delete|update",
	USER: "read|write",
	MODERATOR: "read|write|update",
});

// ============================================================================
// CORE SCHEMAS
// ============================================================================
const roleSchema = z.object({
	_id: z.string().optional(),
	role: UserRole,
	access: AccessEnum,
	isActive: z.boolean().default(true),
	description: z.string().optional(),
});

export const userSchema = z.object({
	_id: z.string(),
	email: z.email(),
	firstname: z.string().min(2).max(100).optional(),
	lastname: z.string().min(2).max(100).optional(),
	login: z.string().min(3).max(50),
	isBan: z.boolean().default(false),
	isConfirmed: z.boolean().default(false),
	role: z.union([roleSchema, z.string()]), // может быть ID роли или объект роли
	password: z.string(), // опционально, если используется для аутентификации
	createdAt: z.date().optional(), // опционально, если используется для аутентификации
	updatedAt: z.date().optional(), // опционально, если используется для аутентификации
});

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
