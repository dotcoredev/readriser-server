import z from "zod";

export const createUserDto = z
	.object({
		login: z
			.string({
				error: "login обязательное поле",
			})
			.min(3, {
				error: "login должен содержать не менее 3 символов",
			}),
		password: z
			.string({
				error: "password обязательное поле",
			})
			.min(6, {
				error: "password должен содержать не менее 6 символов",
			}),
		repeat_password: z.string({
			error: "repeat_password обязательное поле",
		}),
		email: z.email({
			error: "email обязательное поле",
		}),
	})
	.refine((data) => data.password === data.repeat_password, {
		message: "Пароли не совпадают",
	});

export type CreateUserDto = z.infer<typeof createUserDto>;
