import LoginID from "@loginid/websdk3";
import CognitoPasskeyAPI from "../services/cognitoPasskeys";
import {CognitoUserSession} from "amazon-cognito-identity-js";
import {parseJwt} from "../utils/encodes";
import Cognito, {
	CustomAuthentication,
	CustomAuthenticationOptions,
} from "../cognito";
import { 
	PasskeyCollection,
	PasskeyResult,
} from "../services/models/cognitoPasskeys";

/**
 * LoginIDCognitoWebSDK class provides methods for adding and signing in with a passkey using FIDO2 operations.
 */
class LoginIDCognitoWebSDK {
	private cognito: Cognito;
	private passkeyApi: CognitoPasskeyAPI = new CognitoPasskeyAPI("");

	/**
	 * Constructor for the LoginIDCognitoWebSDK class.
	 *
	 * @param {string} userPoolId - The ID of the Cognito User Pool.
	 * @param {string} clientId - The client ID associated with the User Pool.
	 * @param {string} passkeyApiBaseUrl - The base URL for the Passkey API.
	 */
	constructor(userPoolId: string, clientId: string, passkeyApiBaseUrl = "") {
		this.cognito = new Cognito(userPoolId, clientId);
		if (passkeyApiBaseUrl) {
			this.passkeyApi = new CognitoPasskeyAPI(passkeyApiBaseUrl);
		}
	}

	/**
	 * Adds a passkey for the specified username using FIDO2 create operation.
	 *
	 * @param {string} username - The username of the Cognito user.
	 * @param {string} idToken - The Cognito ID token associated with the user.
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
	 * @param {CustomAuthenticationOptions} options - Additional options for custom authentication.
	 * @returns {Promise<CognitoUserSession>} - A promise resolving to the Cognito user session.
	 */
	public async signInWithConditionalUI(
		options?: CustomAuthenticationOptions
	): Promise<CognitoUserSession> {
		const lid = new LoginID({baseUrl: "", appId: ""});
		const lidOptions = {
			autoFill: true,
			...options?.abortSignal && {abortSignal: options.abortSignal},
		}
		const init = await this.passkeyApi.passkeyAuthInit();
		const publicKey: any = await lid.getNavigatorCredential(init, lidOptions);
		const {jwtAccess} =await this.passkeyApi.passkeyAuthComplete(publicKey);
		return await this.signInWithAccessToken(jwtAccess, options);
	}

	/**
	 * Lists all passkeys for a given user.
	 *
	 * This method retrieves a collection of passkeys associated with the provided Cognito
	 * idToken. It interacts with the passkey API to fetch the list.
	 *
	 * @param {string} idToken - The Cognito ID token of the user.
	 * @returns {Promise<PasskeyCollection>} - A promise resolving to a collection of passkeys data.
	 */
	public async listPasskeys(
		idToken: string
	): Promise<PasskeyCollection> {
		return await this.passkeyApi.listPasskeys(idToken);
	}

	/**
	 * Renames a specified passkey.
	 *
	 * This method updates the name of a passkey identified by the passkeyId.
	 * It requires the user's Cognito idToken and the new name for the passkey.
	 *
	 * @param {string} idToken - The Cognito ID token of the user.
	 * @param {string} passkeyId - The unique identifier of the passkey.
	 * @param {string} name - The new name for the passkey.
	 * @returns {Promise<null>} - A promise resolving to null upon successful renaming.
	 */
	public async renamePasskey(
		idToken: string,
		passkeyId: string,
		name: string
	): Promise<null> {
		return await this.passkeyApi.renamePasskey(idToken, passkeyId, name);
	}

	/**
	 * Deletes a specified passkey.
	 *
	 * This method removes a passkey identified by the passkeyId from the user's account.
	 * It requires the user's Cognito idToken and the unique identifier of the passkey.
	 *
	 * @param {string} idToken - The Cognito ID token of the user.
	 * @param {string} passkeyId - The unique identifier of the passkey.
	 * @returns {Promise<null>} - A promise resolving to null upon successful deletion.
	 */
	public async deletePasskey(
		idToken: string,
		passkeyId: string
	): Promise<null> {
		return await this.passkeyApi.deletePasskey(idToken, passkeyId);
	}
}

export default LoginIDCognitoWebSDK;
