/**
 * Base HTTP class for making API requests.
 *
 * This class provides methods to perform HTTP GET, POST, PUT, and DELETE requests.
 * It includes a method to set the base URL and handles JSON response parsing.
 */
class HTTP {
    private baseUrl: string;

    /**
     * Creates an instance of the HTTP class.
     *
     * @param {string} baseUrl - The base URL for the API.
     */
    constructor(baseUrl: string) {
        this.baseUrl = baseUrl;
    }

    /**
     * Performs an HTTP request.
     *
     * This method handles the actual HTTP request, including setting headers and 
     * parsing the JSON response.
     *
     * @param {string} url - The URL endpoint for the request.
     * @param {string} method - The HTTP method (GET, POST, PUT, DELETE).
     * @param {any} body - The request body (for POST and PUT requests).
     * @param {HeadersInit} headers - Additional headers for the request.
     * @returns {Promise<T>} - A promise resolving to the response data.
     */
    private async request<T>(url: string, method: string, body?: any, headers?: HeadersInit): Promise<T> {
        const response = await fetch(`${this.baseUrl}${url}`, {
            method,
            headers: {
                'Content-Type': 'application/json',
                ...headers
            },
            body: body ? JSON.stringify(body) : null,
        });

        if (response.status === 204) {
            return null as T;
        }

        const data = await response.json();
        if (!response.ok) {
            // maybe create new error type
            throw data;
        }

        return data as T;
    }

    /**
     * Performs an HTTP GET request.
     *
     * @template T
     * @param {string} url - The URL endpoint for the GET request.
     * @param {HeadersInit} headers - Additional headers for the request.
     * @returns {Promise<T>} - A promise resolving to the response data.
     */
    async get<T>(url: string, headers?: HeadersInit): Promise<T> {
        return this.request<T>(url, 'GET', null, headers);
    }

    /**
     * Performs an HTTP POST request.
     *
     * @template T
     * @param {string} url - The URL endpoint for the POST request.
     * @param {any} body - The request body.
     * @param {HeadersInit} headers - Additional headers for the request.
     * @returns {Promise<T>} - A promise resolving to the response data.
     */
    async post<T>(url: string, body?: any, headers?: HeadersInit): Promise<T> {
        return this.request<T>(url, 'POST', body, headers);
    }

    /**
     * Performs an HTTP PUT request.
     *
     * @template T
     * @param {string} url - The URL endpoint for the PUT request.
     * @param {any} body - The request body.
     * @param {HeadersInit} headers - Additional headers for the request.
     * @returns {Promise<T>} - A promise resolving to the response data.
     */
    async put<T>(url: string, body?: any, headers?: HeadersInit): Promise<T> {
        return this.request<T>(url, 'PUT', body, headers);
    }

    /**
     * Performs an HTTP DELETE request.
     *
     * @template T
     * @param {string} url - The URL endpoint for the DELETE request.
     * @param {HeadersInit} headers - Additional headers for the request.
     * @returns {Promise<T>} - A promise resolving to the response data.
     */
    async delete<T>(url: string, headers?: HeadersInit): Promise<T> {
        return this.request<T>(url, 'DELETE', null, headers);
    }

    /**
     * Gets the base URL for the API.
     *
     * @returns {string} - The base URL.
     */
    getBaseUrl(): string {
        return this.baseUrl;
    }
}

export default HTTP;
