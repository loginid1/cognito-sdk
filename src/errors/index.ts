/**
 * Custom error class for handling Passkey API errors.
 *
 * This class extends the built-in Error class and adds support for error codes.
 * It includes a static method to create an instance from a payload object.
 */
export class PasskeyAPIError extends Error {
    /**
     * Creates an instance of PasskeyAPIError from a payload object.
     *
     * This static method extracts the error message and code from the payload object
     * and returns a new instance of PasskeyAPIError.
     *
     * @param {any} payload - The error payload from the API response.
     * @returns {PasskeyAPIError} - A new instance of PasskeyAPIError.
     */
    static fromPayload(payload: any): PasskeyAPIError {
        if (payload?.msg) {
            return new PasskeyAPIError(payload.msg, payload.msgCode);
        } else if (payload?.message) {
            return new PasskeyAPIError(payload.message);
        } else {
            return new PasskeyAPIError("Unknown error");
        }
    }

    public msgCode?: string;

    /**
     * Creates an instance of PasskeyAPIError.
     *
     * @param {string} message - The error message.
     * @param {string} [msgCode] - An optional error code.
     */
    constructor(message: string, msgCode?: string) {
        super(message);
        this.name = "Passkey API Error";
        this.msgCode = msgCode;
    }
}
