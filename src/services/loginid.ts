import HTTP from "./http";
import {PasskeyAPIError} from "../errors/";
import {
    CognitoWebhookResponse,
    PasskeyResult,
} from "./models/loginid";

/**
 * API class for handling LoginID FIDO2 service.
 *
 * This class extends the HTTP class and provides methods to interact with the 
 * LoginID FIDO2 service, for handling authentication processes.
 */
class LoginIDService extends HTTP {
    /**
     * Creates an instance of the LoginIDService.
     *
     * @param {string} baseUrl - The base URL for the LoginID FIDO2 API.
     */
    constructor(baseUrl: string) {
        super(baseUrl);
    }

    /**
     * Retrieves the application ID from the base URL.
     *
     * This method extracts the application ID from the LoginID base URL using a regular expression pattern.
     * The application ID is typically a UUID string present in the subdomain of the base URL.
     *
     * @returns {string} - The extracted application ID.
     * @throws {Error} - Throws an error if the base URL does not match the expected pattern.
     */
    public getAppId(): string {
        const pattern = /https:\/\/([0-9a-fA-F-]+)\.api\..*\.loginid\.io/;
        const match = this.getBaseUrl().match(pattern);
        if (match) {
            return match[1];
        } else {
            throw new Error("Invalid LoginID base URL");
        }
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
     * Completes the passkey registration process.
     *
     * @param {RegCompleteRequestBody} body - The request body containing the registration completion details.
     * @returns {Promise<PasskeyResult>} - A promise resolving to the registration completion result.
     */
    async passkeyRegComplete(body: any): Promise<PasskeyResult> {
        return this.execute(async() => {
            return await this.post<PasskeyResult>(`/fido2/v2/reg/complete`, body);
        });
    }

    /**
     * Exchanges a Cognito token for a LoginID token.
     *
     * This method sends a POST request to the LoginID API to exchange the provided Cognito token
     * for a LoginID token.
     *
     * @param {string} token - The Cognito token to be exchanged.
     * @returns {Promise<CognitoWebhookResponse>} - A promise resolving to the `CognitoWebhookResponse` containing the LoginID token.
     */
    async exchangeCognitoToken(token: string): Promise<CognitoWebhookResponse> {
        return this.execute(async() => {
            return await this.post<CognitoWebhookResponse>(`/webhook/cognito/passkeyAuthorize`, {token});
        });
    }
}

export default LoginIDService;
