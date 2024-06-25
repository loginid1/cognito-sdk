import LoginID, { AuthenticateWithPasskeysOptions, PasskeyCollection } from "@loginid/websdk3";
import LoginIDService from "../services/loginid";
import { parseJwt } from "../utils/encodes";
import { CognitoUser, CognitoUserSession } from "amazon-cognito-identity-js";
import Cognito, {
	CustomAuthentication,
	CustomAuthenticationOptions,
} from "../cognito";
import { getRandomString } from "../utils/random";
import { LoginidAPIError } from "../errors";



/**
 * LoginIDCognitoWebSDK class provides methods for adding and signing in with a passkey using FIDO2 operations.
 */
class LoginIDCognitoWebSDK {
	private cognito: Cognito;
	private loginIDService: LoginIDService;
	private lid: LoginID;
	private currentCognitoUser: CognitoUser | null = null;

	/**
	 * Constructor for the LoginIDCognitoWebSDK class.
	 *
	 * @param {string} userPoolId - The ID of the Cognito User Pool.
	 * @param {string} clientId - The client ID associated with the User Pool.
	 * @param {string} baseUrl - The base URL for the LoginID API.
	 */
	constructor(userPoolId: string, clientId: string, baseUrl: string) {
		this.loginIDService = new LoginIDService(baseUrl);
		this.lid = new LoginID({ baseUrl: baseUrl, appId: this.loginIDService.getAppId() });
		this.cognito = new Cognito(this.loginIDService, this.lid, userPoolId, clientId);
	}

	/**
	 * Refreshes the LoginID token if the user is not logged in.
	 *
	 * This method checks if the user is logged in via the LoginID webhook service. If the user is not logged in,
	 * it exchanges the provided Cognito ID token for a LoginID token and sets it as a cookie.
	 *
	 * @param {string} idToken - The Cognito ID token of the user.
	 * @returns {Promise<void>} - A promise resolving to void upon successful token refresh.
	 */
	private async refreshLoginIDToken(
		idToken: string
	) {
		if (!this.lid.isLoggedIn()) {
			const { token } = await this.loginIDService.exchangeCognitoToken(idToken);
			this.lid.setJwtCookie(token);
		}
	}

	/**
	 * Signup with an account without password [randomly generated in background]
	 * 
	 * @param email 
	 * @returns 
	 */
	public async signUpPasswordless(email: string): Promise<CognitoUser> {
		const password = "LID!" + getRandomString(30);
		return await this.cognito.signUp(email, password);
	}

	/**
	 * Adds a passkey for the specified username using FIDO2 create operation.
	 *
	 * @param {string} username - The username of the Cognito user.
	 * @param {string} idToken (optional) - The Cognito ID token associated with the user.
	 * @param {CustomAuthenticationOptions} options - Additional options for custom authentication.
	 * @returns {Promise<CognitoUserSession>} - A promise resolving to the Cognito user session.
	 */
	public async addPasskey(
		username: string,
		idToken?: string,
		options?: CustomAuthenticationOptions
	): Promise<CognitoUserSession> {
		let token = idToken || null;
		if (!token) {
			token = this.cognito.getCurrentCognitoIdToken();
		}
		if (token) {
			return this.cognito.customAuthenticationPasskey(
				username,
				token,
				CustomAuthentication.FIDO2_CREATE,
				options || {}
			);
		} else {
			return Promise.reject(new LoginidAPIError("not authorized"))
		}
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
		options?: CustomAuthenticationOptions,
	): Promise<CognitoUserSession> {
		//const { jwtAccess } = await this.lid.authenticateWithPasskey(username, options)
		return await this.cognito.customAuthenticationPasskey(username, "", CustomAuthentication.FIDO2_GET, options || {})
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
	private async signInWithAccessToken(
		accessJwt: string,
		options?: CustomAuthenticationOptions
	): Promise<CognitoUserSession> {
		const { username } = parseJwt(accessJwt);
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
		const lidOptions = {
			...options,
			autoFill: true,
		}
		const { jwtAccess } = await this.lid.authenticateWithPasskey("", lidOptions);
		return await this.signInWithAccessToken(jwtAccess, options);
	}


	/**
	 * Signs in with passkey autofill (conditional) UI using LoginID SDK.
	 *
	 * This method initiates a sign-in process with conditional UI elements 
	 * using the LoginID SDK. It leverages FIDO2 WebAuthn to provide a secure, 
	 * usernameless authentication.
	 *
	 * @param {CustomAuthenticationOptions} options - Additional options for custom authentication.
	 * @returns {Promise<CognitoUserSession>} - A promise resolving to the Cognito user session.
	 */
	public async signInWithPasskeyAutofill(
		options?: CustomAuthenticationOptions
	): Promise<CognitoUserSession> {
		const isAvailable = await window.PublicKeyCredential?.isConditionalMediationAvailable();
		if (isAvailable) {
			const lidOptions = <AuthenticateWithPasskeysOptions>{
				abortSignal: options?.abortController?.signal,
				autoFill: true,
			}

			const { jwtAccess, deviceID } = await this.lid.authenticateWithPasskey("", lidOptions);
			if (deviceID) {
				// parse username from jwt
				const ljwt = parseJwt(jwtAccess);
				this.loginIDService.saveTrustedDevice(ljwt.username, deviceID);
			}
			return await this.signInWithAccessToken(jwtAccess, options);
		} else {
			return Promise.reject(new LoginidAPIError("not available"));
		}
	}

	/**
	 * Initializes the email OTP authentication process for a user.
	 *
	 * This method initiates the email OTP authentication process for a given email address.
	 * It sets the current Cognito user and prepares them for completing the OTP verification.
	 *
	 * @param {string} email - The email address of the user.
	 * @param {CustomAuthenticationOptions} options - Additional options for custom authentication.
	 * @returns {Promise<null>} - A promise resolving to null upon successful initialization.
	 */
	public async initializeEmailOTP(
		email: string, options?: CustomAuthenticationOptions
	): Promise<null> {
		const user = await this.cognito.customAuthenticationInit(
			email,
			CustomAuthentication.EMAIL_OTP,
			options || {}
		);
		this.currentCognitoUser = user;
		return null;
	}

	/**
	 * Completes the email OTP authentication process for a user.
	 *
	 * This method completes the email OTP authentication process by verifying the OTP provided by the user.
	 * It finalizes the custom authentication and returns the user session.
	 *
	 * @param {string} otp - The one-time password (OTP) received by the user via email.
	 * @param {CustomAuthenticationOptions} options - Additional options for custom authentication.
	 * @returns {Promise<CognitoUserSession | null>} - A promise resolving to the Cognito user session or null if authentication fails.
	 * @throws {Error} - Throws an error if no user is initialized for email OTP.
	 */
	public async completeEmailOTP(
		otp: string, options?: CustomAuthenticationOptions
	): Promise<CognitoUserSession | null> {
		if (this.currentCognitoUser === null) {
			throw new Error("No user initialized for email OTP");
		}
		return this.cognito.customAuthenticationComplete(
			this.currentCognitoUser,
			otp,
			CustomAuthentication.EMAIL_OTP,
			options || {}
		)
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
		idToken?: string
	): Promise<PasskeyCollection> {
		let token = idToken || null;
		if (!token) {
			token = this.cognito.getCurrentCognitoIdToken();
		}
		if (token) {
			//await this.refreshLoginIDToken(token);
			const lidToken = await this.loginIDService.exchangeCognitoToken(token);
			return await this.loginIDService.listPasskeys(lidToken.token);
			//return await this.lid.listPasskeys()
		} else {
			return Promise.reject(new LoginidAPIError("not authorized"));
		}
	}

	/**
	 * Renames a specified passkey.
	 *
	 * This method updates the name of a passkey identified by the passkeyId.
	 * It requires the user's Cognito idToken and the new name for the passkey.
	 *
	 * @param {string} passkeyId - The unique identifier of the passkey.
	 * @param {string} name - The new name for the passkey.
	 * @param {string} idToken - The Cognito ID token of the user.
	 * @returns {Promise<null>} - A promise resolving to null upon successful renaming.
	 */
	public async renamePasskey(
		passkeyId: string,
		name: string,
		idToken?: string,
	): Promise<null> {
		let token = idToken || null;
		if (!token) {
			token = this.cognito.getCurrentCognitoIdToken();
		}
		if (token) {
			await this.refreshLoginIDToken(token);
			return await this.lid.renamePasskey(passkeyId, name);
		} else {
			return Promise.reject(new LoginidAPIError("not authorized"));
		}
	}

	/**
	 * Deletes a specified passkey.
	 *
	 * This method removes a passkey identified by the passkeyId from the user's account.
	 * It requires the user's Cognito idToken and the unique identifier of the passkey.
	 *
	 * @param {string} passkeyId - The unique identifier of the passkey.
	 * @param {string} idToken - The Cognito ID token of the user.
	 * @returns {Promise<null>} - A promise resolving to null upon successful deletion.
	 */
	public async deletePasskey(
		passkeyId: string,
		idToken?: string,
	): Promise<null> {
		let token = idToken || null;
		if (!token) {
			token = this.cognito.getCurrentCognitoIdToken();
		}
		if (token) {
			await this.refreshLoginIDToken(token);
			return await this.lid.deletePasskey(passkeyId);
		} else {
			return Promise.reject(new LoginidAPIError("not authorized"));
		}
	}

	/**
	 * signOut current user 
	 */
	public signOut() {
		this.cognito.signOut();
	}

	/**
	 * 
	 * @returns current username
	 */
	public getCurrentUsername(): string | null {
		return this.cognito.currentUsername();
	}
}

export default LoginIDCognitoWebSDK;
