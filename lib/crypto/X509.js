"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.X509 = void 0;
const tslib_1 = require("tslib");
const forge = tslib_1.__importStar(require("node-forge"));
const ab2str = require("arraybuffer-to-string");
class X509 {
    // missing class validator
    /**
     * Creates a self signed certificate generated from JWK RSA with PEM format
     * @param rsaPEM PEM formatted RSA Key
     */
    static createSelfSignedCertificateFromRSA(rsaPEMPrivate, rsaPEMPublic, info) {
        const cert = forge.pki.createCertificate();
        cert.publicKey = forge.pki.publicKeyFromPem(rsaPEMPublic);
        // alternatively set public key from a csr
        //cert.publicKey = csr.publicKey;
        // NOTE: serialNumber is the hex encoded value of an ASN.1 INTEGER.
        // Conforming CAs should ensure serialNumber is:
        // - no more than 20 octets
        // - non-negative (prefix a '00' if your value starts with a '1' bit)
        cert.serialNumber = '01';
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date();
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
        const attrs = [{
                name: 'commonName',
                value: info.commonName
            }, {
                name: 'countryName',
                value: info.countryName
            }, {
                shortName: 'ST',
                value: info.stateOrProvinceName
            }, {
                name: 'localityName',
                value: info.localityName
            }, {
                name: 'organizationName',
                value: info.organizationName
            }, {
                shortName: 'OU',
                value: info.organizationalUnitName
            }];
        cert.setSubject(attrs);
        // alternatively set subject from a csr
        //cert.setSubject(csr.subject.attributes);
        cert.setIssuer(attrs);
        cert.setExtensions([{
                name: 'basicConstraints',
                cA: true
            }, {
                name: 'keyUsage',
                keyCertSign: true,
                digitalSignature: true,
                nonRepudiation: true,
                keyEncipherment: true,
                dataEncipherment: true
            }, {
                name: 'extKeyUsage',
                serverAuth: true,
                clientAuth: true,
                codeSigning: true,
                emailProtection: true,
                timeStamping: true
            }, {
                name: 'nsCertType',
                client: true,
                server: true,
                email: true,
                objsign: true,
                sslCA: true,
                emailCA: true,
                objCA: true
            }, {
                name: 'subjectAltName',
                altNames: [{
                        type: 6,
                        value: 'http://example.org/webid#me'
                    }, {
                        type: 7,
                        ip: '127.0.0.1'
                    }]
            }, {
                name: 'subjectKeyIdentifier'
            }]);
        /* alternatively set extensions from a csr
        const extensions = csr.getAttribute({name: 'extensionRequest'}).extensions;
        // optionally add more extensions
        extensions.push.apply(extensions, [{
          name: 'basicConstraints',
          cA: true
        }, {
          name: 'keyUsage',
          keyCertSign: true,
          digitalSignature: true,
          nonRepudiation: true,
          keyEncipherment: true,
          dataEncipherment: true
        }]);
        cert.setExtensions(extensions);
        */
        // self-sign certificate
        const pvk = rsaPEMPrivate;
        cert.sign(forge.pki.privateKeyFromPem(pvk));
        // convert a Forge certificate to PEM
        const pem = forge.pki.certificateToPem(cert);
        return pem;
    }
}
exports.X509 = X509;
//# sourceMappingURL=X509.js.map