/* eslint-disable @typescript-eslint/no-unused-vars */
import { ConflictException, Injectable } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { UsersService } from "src/users/users.service";
import { CreateUserDto } from "./dto/signup.dto";
import { ISignupResponse } from "./interfaces/signup.interface";

@Injectable()
export class AuthService {
	constructor(
		private readonly usersService: UsersService,
		private readonly jwtService: JwtService,
	) {}

	async signup(dto: CreateUserDto): Promise<ISignupResponse> {
		const findedUser = await this.usersService.getByEmail(dto.email);

		if (findedUser)
			throw new ConflictException(
				"Пользователь с таким email уже существует",
			);
		const createdUser = await this.usersService.create(dto);
		const { password, ...user } = createdUser;

		return {
			user,
			access_token: this.jwtService.sign({
				email: user?.email,
				_id: user?._id,
			}),
		};
	}
}
