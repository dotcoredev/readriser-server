import { Body, Controller, Post } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { CreateUserDto, createUserDto } from "./dto/signup.dto";
import { User } from "@/users/model/user.model";
import { ZodPipe } from "@/common/pipes/zod/zod.pipe";

@Controller("auth")
export class AuthController {
	constructor(private readonly authService: AuthService) {}

	signin() {
		// Implement your signin logic here
	}

	@Post("signup")
	signup(
		// eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-argument
		@Body(new ZodPipe(createUserDto)) dto: CreateUserDto,
	): Promise<Partial<User>> {
		return this.authService.signup(dto);
	}
}
