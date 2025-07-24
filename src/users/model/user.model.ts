import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import mongoose, { HydratedDocument } from "mongoose";
import * as bcrypt from "bcrypt";
import { Role } from "./role.model";

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
		type: mongoose.Schema.Types.ObjectId,
		ref: Role.name,
	})
	role: Role;
}

// Интерфейс для документа пользователя
// Используется для типизации пользователя в Mongoose
// Не забываем исключать пароль из ответа
export type UserDocument = HydratedDocument<User>;

// Схема пользователя для Mongoose
export const UserSchema = SchemaFactory.createForClass(User);

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
