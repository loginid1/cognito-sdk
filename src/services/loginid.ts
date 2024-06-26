import HTTP from './http'
import { LoginidAPIError } from '../errors'
import { AuthCompleteRequestBody, AuthInit, AuthInitRequestBody, DeviceInfo, PasskeyCollection, PasskeyResult, RegCompleteRequestBody, RegInit, RegInitRequestBody } from '@loginid/websdk3'
import { CognitoWebhookResponse } from './models/loginid'
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
    super(baseUrl)
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
    }
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
    const pattern = /https:\/\/([0-9a-fA-F-]+)\.api\..*\.loginid\.io/
    const match = this.getBaseUrl().match(pattern)
    if (match) {
      return match[1]
    } else {
      throw new Error('Invalid LoginID base URL')
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
     * @throws {LoginidAPIError} - Throws an error if the API call fails.
     */
  private async execute<T>(callback: () => Promise<T>) {
    if (!this.getBaseUrl()) {
      throw new Error('PasskeyAPI base URL is not set')
    }
    try {
      return await callback()
    } catch (error) {
      throw LoginidAPIError.fromPayload(error)
    }
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
    return this.execute(async () => {
      return await this.post<CognitoWebhookResponse>('/webhook/cognito/passkeyAuthorize', { token })
    })
  }


  /**
     * Initiates the passkey registration process.
     *
     * @returns {Promise<RegInit>} - A promise resolving to the registration initiation response for passkeys.
     */
  async passkeyRegInit(request: RegInitRequestBody, token: string): Promise<RegInit> {
    return this.execute(async () => {
      return await this.post<RegInit>('/fido2/v2/reg/init', request, this.setBearerToken(token))
    })
  }

  /**
     * Completes the passkey registration process.
     *
     * @param {RegCompleteRequestBody} body - The request body containing the registration completion details.
     * @returns {Promise<PasskeyResult>} - A promise resolving to the registration completion result.
     */
  async passkeyRegComplete(body: RegCompleteRequestBody): Promise<PasskeyResult> {
    return this.execute(async () => {
      return await this.post<PasskeyResult>('/fido2/v2/reg/complete', body)
    })
  }

  /**
     * Initiates the passkey authentication process.
     *
     * @returns {Promise<AuthInit>} - A promise resolving to the authentication initiation response for passkeys.
     */
  async passkeyAuthInit(request: AuthInitRequestBody): Promise<AuthInit> {
    return this.execute(async () => {
      return await this.post<AuthInit>('/fido2/v2/auth/init', request)
    })
  }

  /**
     * Completes the passkey authentication process.
     *
     * @param {AuthCompleteRequestBody} body - The request body containing the authentication completion details.
     * @returns {Promise<PasskeyResult>} - A promise resolving to the authentication completion result.
     */
  async passkeyAuthComplete(body: AuthCompleteRequestBody): Promise<PasskeyResult> {
    return this.execute(async () => {
      return await this.post<PasskeyResult>('/fido2/v2/auth/complete', body)
    })
  }

  /**
     * Lists all passkeys for the authenticated user.
     *
     * @param {string} token - The bearer token for authentication. The token is the Cognito ID token.
     * @returns {Promise<PasskeyCollection>} - A promise resolving to a collection of passkeys.
     */
  async listPasskeys(token: string): Promise<PasskeyCollection> {
    return this.execute(async () => {
      return await this.get<PasskeyCollection>('/fido2/v2/passkeys', this.setBearerToken(token))
    })
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
    return this.execute(async () => {
      return await this.put<null>(`/fido2/v2/passkeys/${passkeyId}`, { name }, this.setBearerToken(token))
    })
  }

  /**
     * Deletes a specific passkey.
     *
     * @param {string} token - The bearer token for authentication.
     * @param {string} passkeyId - The unique identifier of the passkey.
     * @returns {Promise<null>} - A promise resolving to null upon successful deletion.
     */
  async deletePasskey(token: string, passkeyId: string): Promise<null> {
    return this.execute(async () => {
      return await this.delete<null>(`/fido2/v2/passkeys/${passkeyId}`, this.setBearerToken(token))
    })
  }


  public getDeviceInfo(username: string): DeviceInfo {
    const device: DeviceInfo = {
      clientType: 'browser',
      screenWidth: window.screen.width,
      screenHeight: window.screen.height,
    }

    const deviceId = this.getTrustedDevice(username)
    if (deviceId) {
      device.deviceId = deviceId
    }


    return device
  }

  public saveTrustedDevice(username: string, deviceID?: string) {

    const key = 'trusted-device.' + username.toLowerCase()
    // store trusted deviceID
    if (deviceID) {
      localStorage.setItem(key, deviceID)
    }

  }
  public getTrustedDevice(username: string): string | null {
    const key = 'trusted-device.' + username.toLowerCase()
    return localStorage.getItem(key)
  }

  public saveHasAutofill(username: string) {

    const key = 'autofill-passkey.' + username.toLowerCase()
    // store autofill
    localStorage.setItem(key, "true")

  }
  public getHasAutofill(username: string): boolean {
    const key = 'autofill-passkey.' + username.toLowerCase()
    return localStorage.getItem(key) ? true : false
  }
}

export default LoginIDService
