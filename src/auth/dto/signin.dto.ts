import z from "zod";

export const signinUserDto = z.object({
	password: z
		.string({
			error: "password обязательное поле",
		})
		.min(6, {
			error: "password должен содержать не менее 6 символов",
		}),

	email: z.email({
		error: "email обязательное поле",
	}),
});

export type SigninUserDto = z.infer<typeof signinUserDto>;
