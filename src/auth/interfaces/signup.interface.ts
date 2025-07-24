export interface ISignupResponse {
	access_token: string;
}

// Интерфейс для токенов доступа
// Используется для передачи токенов в ответах
export interface ITokens {
	access_token: string;
	refresh_token: string;
}
