import {base64ToBuffer, bufferToBase64} from "../utils/encodes";
import {
	PublicKeyAssertionCredential,
	PublicKeyAttestationCredential
} from "./types";

/**
 * Creates a new PublicKeyAttestationCredential using the WebAuthn API.
 *
 * @async
 * @param {object} publicKey - Public key information for creating the credential.
 * @param {string} publicKey.challenge - A base64-encoded challenge.
 * @param {object} publicKey.user - User information.
 * @param {string} publicKey.user.id - A base64-encoded user ID.
 * @param {Array<object>} publicKey.excludeCredentials - Optional list of credentials to exclude.
 * @returns {Promise<PublicKeyAttestationCredential>} - Promise resolving to the attestation object.
 * @throws {Error} - If credential creation fails.
 */
export const create = async (
	publicKey: any
): Promise<PublicKeyAttestationCredential> => {
	const {challenge} = publicKey;

	// Converting base64-encoded challenge and user ID to ArrayBuffer
	publicKey.challenge = base64ToBuffer(publicKey.challenge);
	publicKey.user.id = base64ToBuffer(publicKey.user.id);

	// Converting base64-encoded IDs in excludeCredentials, if present
	if (publicKey.excludeCredentials) {
		for (const credential of publicKey.excludeCredentials) {
			credential.id = base64ToBuffer(credential.id);
		}
	}

	// Creating a new credential using the WebAuthn API
	const credential = (await navigator.credentials.create({
		publicKey,
	})) as PublicKeyCredential;

	// Handling the case where credential creation fails
	if (!credential) {
		throw new Error("Failed to create credential");
	}

	// Extracting information from the response of the created credential
	const response = credential.response as AuthenticatorAttestationResponse;

	const attestation = {
		attestation_response: {
			challenge: challenge,
			id: bufferToBase64(credential.rawId),
			type: credential.type,
			response: {
				attestationObject: bufferToBase64(response.attestationObject),
				clientDataJSON: bufferToBase64(response.clientDataJSON),
				// Including transports if available in the response
				...(response.getTransports && {
					transports: response.getTransports(),
				}),
			},
		},
	};

	return attestation;
};

/**
 * Gets an existing PublicKeyAssertionCredential using the WebAuthn API.
 *
 * @async
 * @param {object} publicKey - Public key information for getting the credential.
 * @param {string} publicKey.challenge - A base64-encoded challenge.
 * @param {Array<object>} publicKey.allowCredentials - Optional list of credentials to allow.
 * @returns {Promise<PublicKeyAssertionCredential>} - Promise resolving to the assertion object.
 * @throws {Error} - If credential authentication fails.
 */
export const get = async (
	publicKey: any
): Promise<PublicKeyAssertionCredential> => {
	const challenge = publicKey.challenge;

	// Converting base64-encoded challenge to ArrayBuffer
	publicKey.challenge = base64ToBuffer(challenge);

	// Converting base64-encoded IDs in allowCredentials, if present
	if (publicKey.allowCredentials) {
		for (const credential of publicKey.allowCredentials) {
			credential.id = base64ToBuffer(credential.id);
		}
	}

	// Getting an existing credential using the WebAuthn API
	const credential = (await navigator.credentials.get({
		publicKey,
	})) as PublicKeyCredential;

	// Handling the case where credential authentication fails
	if (!credential) {
		throw new Error("Failed to authenticate credential");
	}

	// Extracting information from the response of the authenticated credential
	const response = credential.response as AuthenticatorAssertionResponse;

	const assertion = {
		assertion_response: {
			challenge: challenge,
			id: bufferToBase64(credential.rawId),
			type: credential.type,
			response: {
				clientDataJSON: bufferToBase64(response.clientDataJSON),
				signature: bufferToBase64(response.signature),
				authenticatorData: bufferToBase64(response.authenticatorData),
				// Including userHandle if available in the response
				userHandle: response.userHandle ? bufferToBase64(response.userHandle) : null,
			},
		},
	};

	return assertion;
};

export type {
	PublicKeyAssertionCredential,
	PublicKeyAttestationCredential
};
