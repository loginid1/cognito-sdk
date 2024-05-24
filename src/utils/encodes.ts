import {LoginIDAccessJWT} from "./types";

/**
 * Parses the JWT token and returns the payload.
 *
 * @param {string} token - The JWT token to parse.
 * @returns {LoginIDAccessJWT} - The payload of the JWT token.
 */
export function parseJwt(token: string): LoginIDAccessJWT {
    try {
        const parts = token.split(".");
        return JSON.parse(atob(parts[1]));
    } catch {
        throw new Error("Invalid JWT token");
    }
}