import LoginIDSDK from "@loginid/websdk3";
import {defaultDeviceInfo, getUserAgent} from "../utils/browser";
import {CustomAuthenticationOptions, InnerOptions} from "./types";
import {
	AuthenticationDetails,
	CognitoUser,
	CognitoUserPool,
	CognitoUserSession,
	IAuthenticationCallback,
	IAuthenticationDetailsData,
	ICognitoUserData,
} from "amazon-cognito-identity-js";

/**
 * Enumeration representing different types of custom authentication operations.
 */
export enum CustomAuthentication {
	AUTH_PARAMS = "AUTH_PARAMS",
	FIDO2_CREATE = "FIDO2_CREATE",
	FIDO2_GET = "FIDO2_GET",
	ACCESS_JWT = "JWT_ACCESS",
}

/**
 * Cognito class for custom authentication using FIDO2.
 */
class Cognito {
	private userPool: CognitoUserPool;

	/**
	 * Constructor for the Cognito class.
	 *
	 * @param {string} userPoolId - The ID of the Cognito User Pool.
	 * @param {string} clientId - The client ID associated with the User Pool.
	 */
	constructor(userPoolId: string, clientId: string) {
		this.userPool = new CognitoUserPool({
			UserPoolId: userPoolId,
			ClientId: clientId,
		});
	}

	/**
	 * Performs custom authentication using FIDO2 for either create or get operations.
	 *
	 * @param {string} username - The username of the Cognito user.
	 * @param {string} token - The token associated with the user.
	 * @param {CustomAuthentication} type - The type of custom authentication operation (FIDO2_CREATE or FIDO2_GET).
	 * @param {CustomAuthenticationOptions} options - Additional options for custom authentication.
	 * @param {object} options.metaData - Additional metadata for the authentication process.
	 * @param {AttestationOptions} options.attestationOptions - Attestation options for FIDO2 operations.
	 * @returns {Promise<CognitoUserSession>} - A promise resolving to the Cognito user session.
	 */
	public async customAuthenticationPasskey(
		username: string,
		token: string,
		type: CustomAuthentication,
		options: CustomAuthenticationOptions,
	): Promise<CognitoUserSession> {
		return new Promise((resolve, reject) => {
			const lid = new LoginIDSDK({baseUrl: "", appId: ""})
			const authenticationData: IAuthenticationDetailsData = {
				Username: username,
				Password: "",
			};
			const userData: ICognitoUserData = {
				Username: username,
				Pool: this.userPool,
			};

			const authenticationDetails = new AuthenticationDetails(authenticationData);
			const user = new CognitoUser(userData);

			const metaData = options.metaData || {};
			const fullOptions: InnerOptions = {
				idToken: token,
				deviceInfo: defaultDeviceInfo(),
				userAgent: getUserAgent(),
				user: {
					...options.displayName && {displayName: options.displayName},
					...options.usernameType && {usernameType: options.usernameType},
				}
			}

			// Callback object for FIDO2_CREATE operation
			const callbackCreateObj: IAuthenticationCallback = {
				customChallenge: async function (challengParams: any) {
					const clientMetadata = {
						...metaData,
						options: JSON.stringify(fullOptions),
						authentication_type: CustomAuthentication.FIDO2_CREATE,
					};

					if (challengParams?.challenge === CustomAuthentication.AUTH_PARAMS) {
						user.sendCustomChallengeAnswer(
							CustomAuthentication.AUTH_PARAMS,
							this,
							clientMetadata
						);
						return;
					}

					const publicKey = JSON.parse(challengParams.public_key);
					const result = await lid.createNavigatorCredential(publicKey);

					user.sendCustomChallengeAnswer(
						JSON.stringify({...result}),
						this,
						clientMetadata
					);
				},

				onSuccess: function (session: CognitoUserSession) {
					resolve(session);
				},

				onFailure: function (err) {
					reject(err);
				},
			};

			// Callback object for FIDO2_GET operation
			const callbackGetObj: IAuthenticationCallback = {
				customChallenge: async function (challengParams: any) {
					const clientMetadata = {
						...metaData,
						options: JSON.stringify(fullOptions),
						authentication_type: CustomAuthentication.FIDO2_GET,
					};

					if (challengParams?.challenge === CustomAuthentication.AUTH_PARAMS) {
						user.sendCustomChallengeAnswer(
							CustomAuthentication.AUTH_PARAMS,
							this,
							clientMetadata
						);
						return;
					}

					const publicKey = JSON.parse(challengParams.public_key);
					const result = await lid.getNavigatorCredential(publicKey);

					user.sendCustomChallengeAnswer(
						JSON.stringify({...result}),
						this,
						clientMetadata
					);
				},

				onSuccess: function (session: CognitoUserSession) {
					resolve(session);
				},

				onFailure: function (err) {
					reject(err);
				},
			};

			// Callback object for ACCESS_JWT operation
			const callbackJWTObj: IAuthenticationCallback = {
				customChallenge: function (challengParams: any) {
					const clientMetadata = {
						...metaData,
						options: JSON.stringify(fullOptions),
						authentication_type: CustomAuthentication.ACCESS_JWT,
					};

					if (challengParams?.challenge === CustomAuthentication.AUTH_PARAMS) {
						user.sendCustomChallengeAnswer(
							CustomAuthentication.AUTH_PARAMS,
							this,
							clientMetadata
						);
						return;
					}

					user.sendCustomChallengeAnswer(
						token,
						this,
						clientMetadata
					);
				},

				onSuccess: function (session: CognitoUserSession) {
					resolve(session);
				},

				onFailure: function (err) {
					reject(err);
				},
			};

			// Initiating custom authentication based on the specified type
			switch (type) {
				case CustomAuthentication.FIDO2_CREATE:
					user.setAuthenticationFlowType("CUSTOM_AUTH");
					user.initiateAuth(authenticationDetails, callbackCreateObj);
					break;

				case CustomAuthentication.FIDO2_GET:
					user.setAuthenticationFlowType("CUSTOM_AUTH");
					user.initiateAuth(authenticationDetails, callbackGetObj);
					break;

				case CustomAuthentication.ACCESS_JWT:
					user.setAuthenticationFlowType("CUSTOM_AUTH");
					user.initiateAuth(authenticationDetails, callbackJWTObj);
					break;

				default:
					throw new Error("Invalid custom authentication type");
			}
		});
	}
}

export type {CustomAuthenticationOptions};

export default Cognito;
