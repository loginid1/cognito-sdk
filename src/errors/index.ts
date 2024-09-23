/*
 *   Copyright (c) 2024 LoginID Inc
 *   All rights reserved.

 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at

 *   http://www.apache.org/licenses/LICENSE-2.0

 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

/**
 * Custom error class for handling Passkey API errors.
 *
 * This class extends the built-in Error class and adds support for error codes.
 * It includes a static method to create an instance from a payload object.
 */
export class LoginidAPIError extends Error {
  /**
     * Creates an instance of PasskeyAPIError from a payload object.
     *
     * This static method extracts the error message and code from the payload object
     * and returns a new instance of PasskeyAPIError.
     *
     * @param {any} payload - The error payload from the API response.
     * @returns {LoginidAPIError} - A new instance of PasskeyAPIError.
     */
  static fromPayload(payload: any): LoginidAPIError {
    if (payload?.msg) {
      return new LoginidAPIError(payload.msg, payload.msgCode)
    } else if (payload?.message) {
      return new LoginidAPIError(payload.message)
    } else {
      return new LoginidAPIError('Unknown error')
    }
  }

  public msgCode?: string

  /**
     * Creates an instance of PasskeyAPIError.
     *
     * @param {string} message - The error message.
     * @param {string} [msgCode] - An optional error code.
     */
  constructor(message: string, msgCode?: string) {
    super(message)
    this.name = 'Passkey API Error'
    this.msgCode = msgCode
  }
}
