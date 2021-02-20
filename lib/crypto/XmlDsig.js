"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.XmlDsig = void 0;
const tslib_1 = require("tslib");
const forge = tslib_1.__importStar(require("node-forge"));
const xmlbuilder2_1 = require("xmlbuilder2");
const xml_crypto_1 = require("xml-crypto");
function KeyInfoProvider(pem) {
    function getSubjectName(certObj) {
        var subjectFields, fields = ['CN', 'OU', 'O', 'L', 'ST', 'C'];
        if (certObj.subject) {
            subjectFields = fields.reduce(function (subjects, fieldName) {
                var certAttr = certObj.subject.getField(fieldName);
                if (certAttr) {
                    subjects.push(fieldName + '=' + certAttr.value);
                }
                return subjects;
            }, []);
        }
        return Array.isArray(subjectFields) ? subjectFields.join(',') : '';
    }
    this._certificatePEM = pem;
    this.getKeyInfo = function (key, prefix) {
        const base64cert = forge.util.encode64(forge.pem.decode(this._certificatePEM)[0].body);
        const certObj = forge.pki.certificateFromPem(this._certificatePEM);
        prefix = prefix || '';
        prefix = prefix ? prefix + ':' : prefix;
        const cert = `<${prefix}X509Certificate>${base64cert}</${prefix}X509Certificate>`;
        return `<${prefix}X509Data><${prefix}X509SubjectName>${getSubjectName(certObj)}</${prefix}X509SubjectName>${cert}</${prefix}X509Data>`;
    };
    this.getKey = function () {
        return this._certificatePEM;
    };
}
class XmlDsig {
    /**
     * Signs a FE DGI invoice documentt
     * @param signingKey Signing Key, PEM generated from a RSA key
     * @param selfSignedCert Certification generated from a RSA key
     * @param document An XML documents
     */
    static signFEDocument(signingKey, selfSignedCert, document) {
        const sig = new xml_crypto_1.SignedXml();
        sig.addReference("//*[local-name(.)='rFE']", ['http://www.w3.org/2001/10/xml-exc-c14n#',
            'http://www.w3.org/2000/09/xmldsig#enveloped-signature',].reverse(), 'http://www.w3.org/2001/04/xmlenc#sha256', "", "", "", true);
        sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
        sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        sig.signingKey = signingKey;
        sig.keyInfoProvider = new KeyInfoProvider(selfSignedCert);
        sig.computeSignature(document);
        const output = sig.getSignedXml();
        let feSigned = xmlbuilder2_1.create(output).end({ format: 'object' });
        return { xml: output, json: feSigned };
    }
    /**
     * Verifies a FE DGI invoice documentt
     * @param selfSignedCert Certification generated from a RSA key
     * @param document An XML documents
     */
    static verifyFEDocument(selfSignedCert, document) {
        const option = { implicitTransforms: ['http://www.w3.org/2001/10/xml-exc-c14n#',
                'http://www.w3.org/2000/09/xmldsig#enveloped-signature',] };
        const sig = new xml_crypto_1.SignedXml(null, option);
        // sig.addReference("//*[local-name(.)='rFE']", ['http://www.w3.org/2001/10/xml-exc-c14n#',
        //     'http://www.w3.org/2000/09/xmldsig#enveloped-signature',]
        //     , 'http://www.w3.org/2001/04/xmlenc#sha256', "", "", "", true)
        // sig.canonicalizationAlgorithm = '';
        sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        const dom = xmlbuilder2_1.create(document);
        const signature = dom.first().find(n => n.node.nodeName === 'Signature');
        sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
        sig.keyInfoProvider = new xml_crypto_1.FileKeyInfo(selfSignedCert);
        sig.loadSignature(signature.node);
        return sig.checkSignature(document);
    }
}
exports.XmlDsig = XmlDsig;
//# sourceMappingURL=XmlDsig.js.map