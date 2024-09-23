/*
 *   Copyright (c) 2024 LoginID Inc
 *   All rights reserved.

 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at

 *   http://www.apache.org/licenses/LICENSE-2.0

 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

import { DeviceInfo } from '../utils/types'

export type UsernameType = 'email' | 'phone';

export const DEFAULT_MATCH_THRESHOLD = 80

export interface CustomAuthenticationOptions {
	metaData?: object;
	displayName?: string;
	usernameType?: UsernameType;
	abortController?: AbortController;
	matchThreshold?: number;
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


export interface AuthResult {
    idToken: string,
    accessToken: string,
    refreshToken?: string,
    isAuthenticated: boolean,
    isFallback: boolean,
    fallbackOptions?: string[],
}

/**
 * General information about the current user session. Information is obtained from the stored authorization token.
 */
export interface SessionInfo {

	/**
	 * Current authenticated user's username.
	 */
	username: string | null
  

	/**
	 * Current accessToken
	 */
	accessToken: string | null


	/**
	 * Current ID Token 
	 */
	idToken: string | null
}
