import { UserDocument } from "@/users/model/user.model";

export interface ISignupResponse {
	user: Partial<UserDocument>;
	access_token: string;
}
