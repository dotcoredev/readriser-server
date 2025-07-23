import { ConflictException, Injectable } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { UsersService } from "src/users/users.service";
import { CreateUserDto } from "./dto/signup.dto";
import { User } from "@/users/model/user.model";

@Injectable()
export class AuthService {
	constructor(
		private readonly usersService: UsersService,
		private readonly jwtService: JwtService,
	) {}

	async signup(dto: CreateUserDto): Promise<Partial<User>> {
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { repeat_password, ...userData } = dto;

		const findedUser = await this.usersService.getByEmail(userData.email);

		if (findedUser)
			throw new ConflictException(
				"Пользователь с таким email уже существует",
			);
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		const { password, ...user } = await this.usersService.create(userData);
		return user;
	}
}
