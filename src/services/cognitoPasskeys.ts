import HTTP from "./http";
import {PasskeyAPIError} from "../errors/";
import {
    AuthCompleteRequestBody,
    AuthInit,
    PasskeyResult,
    PasskeyCollection
} from "./models/cognitoPasskeys";

/**
 * API class for handling Cognito API Gateway Passkey operations with LoginID (proxy).
 *
 * This class extends the HTTP class and provides methods to interact with the 
 * Cognito Passkey API, including listing, renaming, deleting passkeys, and 
 * handling authentication processes.
 */
class CognitoPasskeyAPI extends HTTP {
    /**
     * Creates an instance of the CognitoPasskeyAPI.
     *
     * @param {string} baseUrl - The base URL for the Passkey API.
     */
    constructor(baseUrl: string) {
        super(baseUrl);
    }

    /**
     * Sets the Authorization header with a bearer token.
     *
     * @param {string} token - The bearer token for authentication.
     * @returns {HeadersInit} - The headers including the Authorization token.
     */
    private setBearerToken(token: string): HeadersInit {
        return {
            Authorization: `Bearer ${token}`
        };
    }

    /**
     * Executes an API call with error handling.
     *
     * This method checks if the base URL is set, then executes the provided callback.
     * If an error occurs, it wraps the error in a PasskeyAPIError.
     *
     * @param {() => Promise<T>} callback - The API call to be executed.
     * @returns {Promise<T>} - A promise resolving to the result of the API call.
     * @throws {PasskeyAPIError} - Throws an error if the API call fails.
     */
    private async execute<T>(callback: () => Promise<T>) {
        if (!this.getBaseUrl()) {
            throw new Error("PasskeyAPI base URL is not set");
        }
        try {
            return await callback();
        } catch (error) {
            throw PasskeyAPIError.fromPayload(error);
        }
    }

    /**
     * Lists all passkeys for the authenticated user.
     *
     * @param {string} token - The bearer token for authentication. The token is the Cognito ID token.
     * @returns {Promise<PasskeyCollection>} - A promise resolving to a collection of passkeys.
     */
    async listPasskeys(token: string): Promise<PasskeyCollection> {
        return this.execute(async() => {
            return await this.get<PasskeyCollection>("/passkeys", this.setBearerToken(token));
        });
    }

    /**
     * Renames a specific passkey.
     *
     * @param {string} token - The bearer token for authentication.
     * @param {string} passkeyId - The unique identifier of the passkey.
     * @param {string} name - The new name for the passkey.
     * @returns {Promise<null>} - A promise resolving to null upon successful renaming.
     */
    async renamePasskey(token: string, passkeyId: string, name: string): Promise<null> {
        return this.execute(async() => {
            return await this.put<null>(`/passkeys/${passkeyId}`, {name}, this.setBearerToken(token));
        });
    }

    /**
     * Deletes a specific passkey.
     *
     * @param {string} token - The bearer token for authentication.
     * @param {string} passkeyId - The unique identifier of the passkey.
     * @returns {Promise<null>} - A promise resolving to null upon successful deletion.
     */
    async deletePasskey(token: string, passkeyId: string): Promise<null> {
        return this.execute(async() => {
            return await this.delete<null>(`/passkeys/${passkeyId}`, this.setBearerToken(token));
        });
    }

    /**
     * Initiates the passkey authentication process.
     *
     * @returns {Promise<AuthInit>} - A promise resolving to the authentication initiation response for passkeys.
     */
    async passkeyAuthInit(): Promise<AuthInit> {
        return this.execute(async() => {
            return await this.post<AuthInit>("/passkeys/auth/init");
        });
    }

    /**
     * Completes the passkey authentication process.
     *
     * @param {AuthCompleteRequestBody} body - The request body containing the authentication completion details.
     * @returns {Promise<PasskeyResult>} - A promise resolving to the authentication completion result.
     */
    async passkeyAuthComplete(body: AuthCompleteRequestBody): Promise<PasskeyResult> {
        return this.execute(async() => {
            return await this.post<PasskeyResult>(`/passkeys/auth/complete`, body);
        });
    }
}

export default CognitoPasskeyAPI;
