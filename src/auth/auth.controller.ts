import { Body, Controller, Post } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { CreateUserDto, createUserDto } from "./dto/signup.dto";
import { ZodPipe } from "@/common/pipes/zod/zod.pipe";
import { ISignupResponse } from "./interfaces/signup.interface";

@Controller("auth")
export class AuthController {
	constructor(private readonly authService: AuthService) {}

	signin() {
		// Implement your signin logic here
	}

	@Post("signup")
	signup(
		@Body(new ZodPipe(createUserDto)) dto: CreateUserDto,
	): Promise<ISignupResponse> {
		return this.authService.signup(dto);
	}
}
