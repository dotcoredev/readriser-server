import { Injectable } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { User, UserDocument } from "./model/user.model";
import { Model } from "mongoose";
import { CreateUserDto } from "@/auth/dto/signup.dto";

@Injectable()
export class UsersService {
	constructor(
		@InjectModel(User.name) private readonly userRepository: Model<User>,
	) {}

	async getAll() {
		return this.userRepository.find().lean().exec();
	}

	async getById(id: string) {
		return this.userRepository.findById(id).lean().exec();
	}

	async getByEmail(email: string) {
		return this.userRepository.findOne({ email }).lean().exec();
	}

	async create(user: CreateUserDto): Promise<UserDocument> {
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { repeat_password, ...fields } = user;

		const newUser = new this.userRepository(fields);
		const savedUser = await newUser.save();

		return savedUser.toJSON<UserDocument>();
	}
}
