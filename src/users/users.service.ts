import { BadRequestException, Injectable } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { User, UserDocument } from "./model/user.model";
import { Model } from "mongoose";
import { CreateUserDto } from "@/auth/dto/signup.dto";
import { AccessEnum, Role, RoleDocument, RoleEnum } from "./model/role.model";

@Injectable()
export class UsersService {
	constructor(
		@InjectModel(User.name) private readonly userRepository: Model<User>,
		@InjectModel(Role.name) private readonly roleRepository: Model<Role>,
	) {}

	async getAll() {
		return this.userRepository.find().lean().exec();
	}

	async getById(id: string) {
		return this.userRepository.findById(id).populate("role").lean().exec();
	}

	async profile(email: string): Promise<Omit<User, "password">> {
		const findUser = await this.getByEmail(email);
		if (!findUser) throw new BadRequestException("Пользователь не найден");

		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...user } = findUser;
		return user;
	}

	async getByEmail(email: string): Promise<User | null> {
		const findUser = await this.userRepository
			.findOne({ email })
			.select("-updatedAt")
			.populate("role", "role access -_id")
			.lean();

		return findUser;
	}

	async create(user: CreateUserDto): Promise<UserDocument | null> {
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { repeat_password, ...fields } = user;
		const getDefaultRole = await this.roleRepository
			.findOne<RoleDocument>({ role: RoleEnum.USER })
			.lean()
			.exec();

		if (!getDefaultRole) {
			throw new Error("Default user role not found");
		}

		const newUser = new this.userRepository({
			...fields,
			role: getDefaultRole,
		});
		const savedUser = await newUser.save();
		return savedUser;
	}

	async createRoles(): Promise<boolean> {
		await this.roleRepository.create({
			role: RoleEnum.ADMIN,
			access: AccessEnum.ADMIN,
			description: "Administrator with full access",
		});

		await this.roleRepository.create({
			role: RoleEnum.MODERATOR,
			access: AccessEnum.MODERATOR,
			description: "Moderator with elevated privileges",
		});

		await this.roleRepository.create({
			role: RoleEnum.USER,
			access: AccessEnum.USER,
			description: "Regular user with limited access",
		});

		return true;
	}
}
