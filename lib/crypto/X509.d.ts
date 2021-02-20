import { X509Info } from './KeyConvert';
export declare class X509 {
    /**
     * Creates a self signed certificate generated from JWK RSA with PEM format
     * @param rsaPEM PEM formatted RSA Key
     */
    static createSelfSignedCertificateFromRSA(rsaPEMPrivate: string, rsaPEMPublic: string, info: X509Info): any;
}
