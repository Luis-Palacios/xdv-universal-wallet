/// <reference types="node" />
export declare class CMSSigner {
    static sign(pemCertificate: string, signingKey: string, content: Buffer, detached?: boolean): any;
    static buf2hex(buffer: any): any;
    static validatePEM(cert: Buffer, pem: string): any;
}
