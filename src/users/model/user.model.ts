import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { HydratedDocument } from "mongoose";

export type UserDocument = HydratedDocument<User>;

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

	@Prop({
		required: true,
	})
	password: string;
}

export const UserSchema = SchemaFactory.createForClass(User);
