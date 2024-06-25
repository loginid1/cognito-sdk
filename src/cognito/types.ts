import { DeviceInfo } from '../utils/types'

export type UsernameType = 'email' | 'phone';

export const DEFAULT_MATCH_THRESHOLD = 80;

export interface CustomAuthenticationOptions {
	metaData?: object;
	displayName?: string;
	usernameType?: UsernameType;
	abortController?: AbortController;
	matchThreshold?: number;
	fallback?: ISignInFallbackCallback;
}

export interface InnerOptions extends CustomAuthenticationOptions {
	idToken?: string;
	deviceInfo?: DeviceInfo;
	userAgent?: string;
	user?: {
		displayName?: string;
		usernameType?: UsernameType;
	}
}

export interface ISignInFallbackCallback {
	onFallback: (username: string, options: string[]) => void;
}
