import * as webauthn from "../webauthn/";
import {AttestationOptions, CustomAuthenticationOptions} from "./types";
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
	 * Converts CustomAuthenticationOptions to AttestationOptions.
	 *
	 * @param {CustomAuthenticationOptions} options - Additional options for custom authentication.
	 * @returns {AttestationOptions} - Attestation options for FIDO2 operations.
	 */
	private handleAttestationOptions(
		options: CustomAuthenticationOptions
	): AttestationOptions {
		const attestationOptions: AttestationOptions = {};

		if (options.attestationOptions?.overrideTimeout !== undefined) {
			attestationOptions["override_timeout_s"] = options.attestationOptions.overrideTimeout;
		}

		if (options.attestationOptions?.requireResidentKey !== undefined) {
			attestationOptions["require_usernameless"] = options.attestationOptions.requireResidentKey;
		}

		return attestationOptions;
	}

	/**
	 * Performs custom authentication using FIDO2 for either create or get operations.
	 *
	 * @param {string} username - The username of the Cognito user.
	 * @param {string} idToken - The ID token associated with the user.
	 * @param {CustomAuthentication} type - The type of custom authentication operation (FIDO2_CREATE or FIDO2_GET).
	 * @param {CustomAuthenticationOptions} options - Additional options for custom authentication.
	 * @param {object} options.metaData - Additional metadata for the authentication process.
	 * @param {AttestationOptions} options.attestationOptions - Attestation options for FIDO2 operations.
	 * @returns {Promise<CognitoUserSession>} - A promise resolving to the Cognito user session.
	 */
	public async customAuthenticationPasskey(
		username: string,
		idToken: string,
		type: CustomAuthentication,
		options: CustomAuthenticationOptions,
	): Promise<CognitoUserSession> {
		return new Promise((resolve, reject) => {
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
			const attestationOptions = this.handleAttestationOptions(options);

			// Callback object for FIDO2_CREATE operation
			const callbackCreateObj: IAuthenticationCallback = {
				customChallenge: async function (challengParams: any) {
					const clientMetadata = {
						...metaData,
						attestation_options: JSON.stringify(attestationOptions),
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
					const result = await webauthn.create(publicKey);

					user.sendCustomChallengeAnswer(
						JSON.stringify({...result, id_token: idToken}),
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
					const result = await webauthn.get(publicKey);

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

				default:
					throw new Error("Invalid custom authentication type");
			}
		});
	}
}

export type {CustomAuthenticationOptions};

export default Cognito;
