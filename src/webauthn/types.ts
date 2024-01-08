export type JSON = string;
export type Base64 = string;

export interface PublicKeyAttestationCredential {
	attestation_response: {
		challenge: string;
		id: Base64;
		type: string;
		response: {
			attestationObject: Base64;
			clientDataJSON: Base64;
		};
	};
}

export interface PublicKeyAssertionCredential {
	assertion_response: {
		challenge: string;
		id: Base64;
		type: string;
		response: {
			clientDataJSON: Base64;
			authenticatorData: Base64;
			signature: Base64;
		};
	};
}
