import LoginID from "@loginid/websdk3";

type GetNavigatorCredentialF = LoginID["getNavigatorCredential"];

export type AuthInit = Parameters<GetNavigatorCredentialF>[0];
export type AuthCompleteRequestBody = ReturnType<GetNavigatorCredentialF>;
