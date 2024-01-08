export interface CustomAuthenticationOptions {
	metaData?: object;
	attestationOptions?: {
		requireResidentKey?: boolean;
		overrideTimeout?: number;
	}
}

export interface AttestationOptions {
	override_timeout_s?: number;
	require_usernameless?: boolean;
}
