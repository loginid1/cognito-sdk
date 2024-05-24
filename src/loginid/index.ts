import LoginID from "@loginid/websdk3";
import {CognitoUserSession} from "amazon-cognito-identity-js";
import {parseJwt} from "../utils/encodes";
import {AuthCompleteRequestBody, AuthInit} from "./types";
import Cognito, {
	CustomAuthentication,
	CustomAuthenticationOptions,
} from "../cognito";

/**
 * LoginIDCognitoWebSDK class provides methods for adding and signing in with a passkey using FIDO2 operations.
 */
class LoginIDCognitoWebSDK {
	private cognito: Cognito;

	/**
	 * Constructor for the LoginIDCognitoWebSDK class.
	 *
	 * @param {string} userPoolId - The ID of the Cognito User Pool.
	 * @param {string} clientId - The client ID associated with the User Pool.
	 */
	constructor(userPoolId: string, clientId: string) {
		this.cognito = new Cognito(userPoolId, clientId);
	}

	/**
	 * Adds a passkey for the specified username using FIDO2 create operation.
	 *
	 * @param {string} username - The username of the Cognito user.
	 * @param {string} idToken - The ID token associated with the user.
	 * @param {CustomAuthenticationOptions} options - Additional options for custom authentication.
	 * @returns {Promise<CognitoUserSession>} - A promise resolving to the Cognito user session.
	 */
	public async addPasskey(
		username: string,
		idToken: string,
		options?: CustomAuthenticationOptions
	): Promise<CognitoUserSession> {
		return this.cognito.customAuthenticationPasskey(
			username,
			idToken,
			CustomAuthentication.FIDO2_CREATE,
			options || {}
		);
	}

	/**
	 * Signs in with a passkey for the specified username using FIDO2 get operation.
	 *
	 * @param {string} username - The username of the Cognito user.
	 * @param {CustomAuthenticationOptions} options - Additional options for custom authentication.
	 * @returns {Promise<CognitoUserSession>} - A promise resolving to the Cognito user session.
	 */
	public async signInPasskey(
		username: string,
		options?: CustomAuthenticationOptions
	): Promise<CognitoUserSession> {
		return this.cognito.customAuthenticationPasskey(
			username,
			"",
			CustomAuthentication.FIDO2_GET,
			options || {}
		);
	}

	/**
	 * Signs in using an access token for the specified username.
	 *
	 * This method performs a custom authentication process using an access token. 
	 * The access token, typically a JWT, is used to authenticate the user without 
	 * requiring their username and password, providing a secure and streamlined login experience.
	 *
	 * @param {string} accessJwt - The access token (JWT) associated with the user.
	 * @param {CustomAuthenticationOptions} options - Additional options for custom authentication.
	 * @returns {Promise<CognitoUserSession>} - A promise resolving to the Cognito user session.
	 */
	public async signInWithAccessToken(
		accessJwt: string,
		options?: CustomAuthenticationOptions
	): Promise<CognitoUserSession> {
		const {username} = parseJwt(accessJwt);
		return this.cognito.customAuthenticationPasskey(
			username,
			accessJwt,
			CustomAuthentication.ACCESS_JWT,
			options || {}
		);
	}

	/**
	 * Signs in with conditional UI using LoginID SDK.
	 *
	 * This method initiates a sign-in process with conditional UI elements 
	 * using the LoginID SDK. It leverages FIDO2 WebAuthn to provide a secure, 
	 * usernameless authentication.
	 *
	 * @param {AuthInit} init - The initialization parameters for authentication.
	 * @param {CustomAuthenticationOptions} options - Additional options for custom authentication.
	 * @returns {Promise<AuthCompleteRequestBody>} - A promise resolving to the authentication complete request body.
	 */
	public async signInWithConditionalUI(
		init: AuthInit,
		options?: CustomAuthenticationOptions
	): Promise<AuthCompleteRequestBody> {
		const lid = new LoginID({baseUrl: "", appId: ""});
		const lidOptions = {
			autoFill: true,
			...options?.abortSignal && {abortSignal: options.abortSignal},
		}
		return await lid.getNavigatorCredential(init, lidOptions);
	}
}

export default LoginIDCognitoWebSDK;
