import { Body, Controller, Post, Req, Res } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { CreateUserDto, createUserDto } from "./dto/signup.dto";
import { ZodPipe } from "@/common/pipes/zod/zod.pipe";
import { ISignupResponse } from "./interfaces/signup.interface";
import { SigninUserDto, signinUserDto } from "./dto/signin.dto";
import type { Request, Response } from "express";

@Controller("auth")
export class AuthController {
	constructor(private readonly authService: AuthService) {}

	@Post("signup")
	signup(
		@Body(new ZodPipe(createUserDto)) dto: CreateUserDto,
		@Res({ passthrough: true }) res: Response,
	): Promise<ISignupResponse> {
		return this.authService.signup(dto, res);
	}

	@Post("signin")
	signin(
		@Body(new ZodPipe(signinUserDto)) dto: SigninUserDto,
		@Res({ passthrough: true }) res: Response,
	): Promise<ISignupResponse> {
		return this.authService.login(dto, res);
	}

	@Post("refresh")
	refresh(
		@Res({ passthrough: true }) res: Response,
		@Req() req: Request,
	): Promise<ISignupResponse> {
		return this.authService.refresh(res, req);
	}

	@Post("logout")
	logout(@Res({ passthrough: true }) res: Response): boolean {
		return this.authService.logout(res);
	}
}
