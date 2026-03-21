export declare const SecretType: {
    readonly AWS_KEY: "AWS_KEY";
    readonly GITHUB_TOKEN: "GITHUB_TOKEN";
    readonly PRIVATE_KEY: "PRIVATE_KEY";
    readonly JWT: "JWT";
    readonly CONNECTION_STRING: "CONNECTION_STRING";
    readonly API_KEY: "API_KEY";
    readonly BEARER_TOKEN: "BEARER_TOKEN";
};
export type SecretType = typeof SecretType[keyof typeof SecretType];
export interface Detection {
    readonly type: SecretType;
    readonly match: string;
    readonly index: number;
}
export interface ScanResult {
    readonly detections: readonly Detection[];
    readonly clean: boolean;
}
export declare const TripwireErrorCode: {
    readonly IO_FAILED: "IO_FAILED";
    readonly PARSE_FAILED: "PARSE_FAILED";
};
export type TripwireErrorCode = typeof TripwireErrorCode[keyof typeof TripwireErrorCode];
export interface TripwireError {
    readonly code: TripwireErrorCode;
    readonly message: string;
}
//# sourceMappingURL=types.d.ts.map