import LoginIDCognitoWebSDK from "./loginid";
import { CustomAuthenticationOptions } from "./cognito";
import { Passkey, PasskeyCollection } from "@loginid/websdk3";
import { ISignInFallbackCallback } from "./cognito/types";

export type { CustomAuthenticationOptions, ISignInFallbackCallback };
export type {PasskeyCollection, Passkey};
export { LoginIDCognitoWebSDK };
