import LoginID, {PasskeyResult as ImportedPasskeyResult} from "@loginid/websdk3";

type GetNavigatorCredentialF = LoginID["getNavigatorCredential"];
type ListPasskeysF = LoginID["listPasskeys"];

export type AuthInit = Parameters<GetNavigatorCredentialF>[0];
export type AuthCompleteRequestBody = ReturnType<GetNavigatorCredentialF>;
export type PasskeyCollection = ReturnType<ListPasskeysF>;
export type PasskeyResult = ImportedPasskeyResult;