import { Controller, Get, Query } from "@nestjs/common";
import { UsersService } from "./users.service";
import { User } from "./model/user.model";
import { ZodPipe } from "@/common/pipes/zod/zod.pipe";
import { ProfileDto, profileDto } from "./dto/profile.dto";

@Controller("users")
export class UsersController {
	constructor(private readonly usersService: UsersService) {}

	@Get("/")
	async getAllUsers() {
		return this.usersService.getAll();
	}

	@Get("/profile")
	async getByEmail(
		@Query(new ZodPipe(profileDto)) dto: ProfileDto,
	): Promise<Omit<User, "password">> {
		return this.usersService.profile(dto.email);
	}

	//@Post("/create-roles")
	//async createRoles(): Promise<boolean> {
	//	return this.usersService.createRoles();
	//}
}
