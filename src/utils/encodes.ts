/**
 * Converts a base64-encoded string to an ArrayBuffer.
 *
 * @param {string} data - The base64-encoded string to convert.
 * @returns {ArrayBuffer} - The resulting ArrayBuffer.
 */
export const base64ToBuffer = (data: string): ArrayBuffer => {
	// Replacing URL-safe characters and decoding the base64 string
	data = data.replace(/-/g, "+").replace(/_/g, "/");
	const binary = atob(data);
	const bytes = new Uint8Array(binary.length);

	// Populating the Uint8Array with binary data
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}

	return bytes.buffer;
};

/**
 * Converts an ArrayBuffer to a base64-encoded string.
 *
 * @param {ArrayBuffer} data - The ArrayBuffer to convert.
 * @returns {string} - The resulting base64-encoded string.
 */
export const bufferToBase64 = (data: ArrayBuffer): string => {
	// Creating a Uint8Array from the ArrayBuffer
	const bytes = new Uint8Array(data);
	let binary = "";

	// Converting Uint8Array to binary string
	for (let i = 0; i < bytes.byteLength; i++) {
		binary += String.fromCharCode(bytes[i]);
	}

	// Encoding the binary string to base64
	const base64 = btoa(binary);

	// Making the base64 string URL-safe
	return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
