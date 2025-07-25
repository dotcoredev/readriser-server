import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { AccessEnum, RoleEnum } from "../interfaces/role-model.interface";

@Schema({
	timestamps: true,
	collection: "roles",
	versionKey: false, // Убирает __v
})
export class Role {
	// Название роли
	// Используется для идентификации роли в системе
	@Prop({
		required: true,
		enum: RoleEnum,
	})
	role: RoleEnum;

	// Права доступа роли
	// Используется для определения, какие действия может выполнять роль
	// Например, роль "admin" может иметь полный доступ, а роль "user" -
	// только чтение и запись
	// Связь с моделью User не требуется, так как роль может быть общей для
	// нескольких пользователей и не зависит от конкретного пользователя
	// Не забываем исключать поле _id из ответа, так как оно не нужно в
	// пользовательском интерфейсе
	@Prop({
		required: true,
		enum: AccessEnum,
	})
	access: AccessEnum;

	// Флаг активности роли
	// Используется для управления доступностью роли в системе
	// Например, если роль неактивна, пользователи с этой ролью не смогут выполнять действия
	// Связь с моделью User не требуется, так как роль может быть неактивной
	// и не использоваться в системе, но при этом существовать в базе данных
	@Prop({
		default: true,
	})
	isActive: boolean;

	@Prop()
	description: string;

	// ID роли
	// Используется для уникальной идентификации роли в системе
	_id: string;
}

// Схема роли для Mongoose
export const RoleSchema = SchemaFactory.createForClass(Role);
