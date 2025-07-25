import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Types } from "mongoose";
import * as bcrypt from "bcrypt";
import { Role } from "./role.model";
import { TUserSchema } from "../dto/user.dto";

// Схема пользователя для Mongoose
// Используется для создания и управления пользователями в базе данных
@Schema({
	timestamps: true,
	collection: "users",
	versionKey: false, // Убирает __v
})
export class User {
	@Prop()
	firstname: string;

	@Prop()
	lastname: string;

	@Prop({
		required: true,
	})
	login: string;

	@Prop({
		unique: true,
		required: true,
		trim: true,
	})
	email: string;

	// Пароль пользователя
	// Хранится в зашифрованном виде
	@Prop({
		required: true,
	})
	password: string;

	// Флаг для блокировки пользователя
	// Используется для временной блокировки пользователя
	@Prop({
		default: false,
	})
	isBan: boolean;

	// Флаг для подтверждения email
	@Prop({
		default: false,
	})
	isConfirmed: boolean;

	// Роль пользователя
	// Используется для определения прав доступа пользователя
	// Связь с моделью Role
	@Prop({
		type: Types.ObjectId,
		ref: Role.name,
	})
	role: Role;

	// Тут не указывается @Prop, т.к. mongoose сам генерирует эти поля.
	// Поля были добавлены для валидной типизации в DTO
	_id: string;
	updatedAt: Date;
	createdAt: Date;
}

// Схема пользователя для Mongoose
export const UserSchema = SchemaFactory.createForClass<TUserSchema>(User);

// Хук для хеширования пароля перед сохранением пользователя
// Используется для безопасности хранения паролей
// Хешируем пароль только если он был изменен
UserSchema.pre("save", async function (next) {
	if (!this.isModified("password")) {
		return next();
	}
	try {
		const saltRounds = process.env.NODE_ENV === "dev" ? 2 : 8;
		this.password = await bcrypt.hash(this.password, saltRounds);
		next();
	} catch (error) {
		next(error as Error);
	}
});
