export type DeviceInfo = {
    clientName?: string;
    clientType?: 'browser' | 'other';
    clientVersion?: string;
    deviceId?: string;
    osArch?: string;
    osName?: string;
    osVersion?: string;
    screenHeight?: number;
    screenWidth?: number;
};

export interface LoginIDAccessJWT {
    username: string;
}