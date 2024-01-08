import {CognitoUserSession} from "amazon-cognito-identity-js";
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
}

export default LoginIDCognitoWebSDK;
