import {DeviceInfo} from '../utils/types'

export type UsernameType = 'email' | 'phone';

export interface CustomAuthenticationOptions {
	metaData?: object;
	displayName?: string;
	usernameType?: UsernameType;
	abortSignal?: AbortSignal;
}

export interface InnerOptions extends CustomAuthenticationOptions{
	idToken?: string;
	deviceInfo?: DeviceInfo;
	userAgent?: string;
	user?: {
		displayName?: string;
		usernameType?: UsernameType;
	}
}
