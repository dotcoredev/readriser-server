import z from "zod";

export const profileDto = z.object({
	email: z.email({
		error: "Некорректный email",
	}),
});

export type ProfileDto = z.infer<typeof profileDto>;
