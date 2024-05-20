import {DeviceInfo} from "../utils/types";

export type UsernameType = "email" | "phone";

export interface CustomAuthenticationOptions {
	metaData?: object;
	displayName?: string;
	usernameType?: UsernameType;
}

export interface InnerOptions extends CustomAuthenticationOptions{
	idToken?: string;
	deviceInfo?: DeviceInfo;
	user?: {
		displayName?: string;
		usernameType?: UsernameType;
	}
}