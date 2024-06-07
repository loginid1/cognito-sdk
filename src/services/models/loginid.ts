
import LoginID, {PasskeyResult as ImportedPasskeyResult} from "@loginid/websdk3";

type CreateNavigatorCredentialF = LoginID["createNavigatorCredential"];

export interface CognitoWebhookResponse {
    token: string;
}

export type RegCompleteRequestBody = ReturnType<CreateNavigatorCredentialF>;
export type PasskeyResult = ImportedPasskeyResult;