import { Injectable } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { User, UserDocument } from "./model/user.model";
import { Model } from "mongoose";

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

	async create(user: Partial<User>): Promise<UserDocument> {
		const newUser = new this.userRepository(user);
		const savedUser = await newUser.save();
		return savedUser.toJSON<UserDocument>();
	}
}
