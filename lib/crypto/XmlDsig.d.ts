export declare class XmlDsig {
    /**
     * Signs a FE DGI invoice documentt
     * @param signingKey Signing Key, PEM generated from a RSA key
     * @param selfSignedCert Certification generated from a RSA key
     * @param document An XML documents
     */
    static signFEDocument(signingKey: string, selfSignedCert: string, document: string): {
        xml: string;
        json: import("xmlbuilder2/lib/interfaces").XMLSerializedAsObject | import("xmlbuilder2/lib/interfaces").XMLSerializedAsObjectArray;
    };
    /**
     * Verifies a FE DGI invoice documentt
     * @param selfSignedCert Certification generated from a RSA key
     * @param document An XML documents
     */
    static verifyFEDocument(selfSignedCert: string, document: string): boolean;
}
