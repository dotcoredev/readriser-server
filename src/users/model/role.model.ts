import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { HydratedDocument } from "mongoose";

export type RoleDocument = HydratedDocument<Role>;

export enum RoleEnum {
	ADMIN = "admin",
	USER = "user",
	MODERATOR = "moderator",
}

export enum AccessEnum {
	ADMIN = "read|write|delete|update",
	USER = "read|write",
	MODERATOR = "read|write|update",
}

@Schema({
	timestamps: true,
	collection: "roles",
	versionKey: false, // Убирает __v
})
export class Role {
	@Prop({
		required: true,
		enum: RoleEnum,
	})
	role: RoleEnum;

	@Prop({
		required: true,
		enum: AccessEnum,
	})
	access: AccessEnum;

	@Prop({
		default: true,
	})
	isActive: boolean;

	@Prop()
	description: string;
}

export const RoleSchema = SchemaFactory.createForClass(Role);
