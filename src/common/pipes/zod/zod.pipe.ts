import { BadRequestException, PipeTransform } from "@nestjs/common";
import { ZodType } from "zod";

export class ZodPipe<T> implements PipeTransform {
	constructor(private readonly schema: ZodType<T>) {}

	transform(value: any): unknown {
		const result = this.schema.safeParse(value);
		if (!result.success) {
			throw new BadRequestException(
				result.error.issues.map((error) => ({
					message: error.message,
				})),
			);
		}
		return result.data;
	}
}
