export enum RoleEnum {
	ADMIN = "admin",
	USER = "user",
	MODERATOR = "moderator",
}

export enum AccessEnum {
	ADMIN = "read|write|delete|update",
	USER = "read|write",
	MODERATOR = "read|write|update",
}
