"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Wallet = exports.KeyStore = exports.WalletOptions = exports.AlgorithmType = void 0;
const tslib_1 = require("tslib");
const filecoinSigner = require('@zondax/filecoin-signing-tools/js');
const pouchdb_1 = tslib_1.__importDefault(require("pouchdb"));
const elliptic_1 = require("elliptic");
const ethers_1 = require("ethers");
const ed25519_hd_key_1 = require("ed25519-hd-key");
const class_validator_1 = require("class-validator");
const JOSEService_1 = require("./JOSEService");
const node_jose_1 = require("node-jose");
// import { createEd25519 } from '../../src/rust/crypto/pkg/zengox_curv';
const JWTService_1 = require("./JWTService");
const KeyConvert_1 = require("./KeyConvert");
const LDCryptoTypes_1 = require("./LDCryptoTypes");
const rxjs_1 = require("rxjs");
const p12 = tslib_1.__importStar(require("p12-pem"));
const utils_1 = require("ethers/lib/utils");
var AlgorithmType;
(function (AlgorithmType) {
    AlgorithmType[AlgorithmType["RSA"] = 0] = "RSA";
    AlgorithmType[AlgorithmType["ES256K"] = 1] = "ES256K";
    AlgorithmType[AlgorithmType["P256"] = 2] = "P256";
    AlgorithmType[AlgorithmType["ED25519"] = 3] = "ED25519";
    AlgorithmType[AlgorithmType["BLS"] = 4] = "BLS";
    AlgorithmType[AlgorithmType["P256_JWK_PUBLIC"] = 5] = "P256_JWK_PUBLIC";
    AlgorithmType[AlgorithmType["ED25519_JWK_PUBLIC"] = 6] = "ED25519_JWK_PUBLIC";
    AlgorithmType[AlgorithmType["ES256K_JWK_PUBLIC"] = 7] = "ES256K_JWK_PUBLIC";
    AlgorithmType[AlgorithmType["RSA_JWK_PUBLIC"] = 8] = "RSA_JWK_PUBLIC";
    AlgorithmType[AlgorithmType["RSA_PEM_PUBLIC"] = 9] = "RSA_PEM_PUBLIC";
})(AlgorithmType = exports.AlgorithmType || (exports.AlgorithmType = {}));
class WalletOptions {
}
tslib_1.__decorate([
    class_validator_1.IsString(),
    class_validator_1.IsDefined()
], WalletOptions.prototype, "password", void 0);
tslib_1.__decorate([
    class_validator_1.IsOptional(),
    class_validator_1.IsString()
], WalletOptions.prototype, "mnemonic", void 0);
exports.WalletOptions = WalletOptions;
class KeyStore {
    constructor() {
    }
}
exports.KeyStore = KeyStore;
class Wallet {
    constructor() {
        this.onRequestPassphraseSubscriber = new rxjs_1.Subject();
        this.onRequestPassphraseWallet = new rxjs_1.Subject();
        this.onSignExternal = new rxjs_1.Subject();
        this.db = new pouchdb_1.default('xdv:web:wallet');
        pouchdb_1.default.plugin(require('crypto-pouch'));
    }
    /**
     * Verifies a filecoin signed transaction
     * @param signature a filecoin signature
     * @param cborContent a filecoint raw transaction
     */
    async verifyFilecoinSignature(signature, cborContent) {
        return filecoinSigner.verifySignature(signature, cborContent);
    }
    /**
     * Signs a filecoin transaction
     * @param transaction a filecoin transaction
     * @param signer Sets the filecoin or lotus signer
     */
    async signFilecoinTransaction(transaction, signer) {
        this.onRequestPassphraseSubscriber.next({ type: 'request_tx', transaction, algorithm: signer.toString() });
        const canUseIt = await this.canUse();
        const tx = filecoinSigner.transactionSerialize(transaction);
        if (canUseIt) {
            let signature;
            const pvk = await this.getFilecoinDeriveChild();
            if (signer === 'filecoin') {
                signature = filecoinSigner.transactionSign(tx, pvk);
            }
            else {
                signature = filecoinSigner.transactionSignLotus(tx, pvk);
            }
            return [null, signature];
        }
        return [new Error('invalid_passphrase')];
    }
    /**
     * Gets a public key from storage
     * @param id
     * @param algorithm
     */
    async getPublicKey(id) {
        const content = await this.db.get(id);
        return await node_jose_1.JWK.asKey(JSON.parse(content.key), 'jwk');
    }
    /**
     * Sets a public key in storage
     * @param id
     * @param algorithm
     * @param value
     */
    async setPublicKey(id, algorithm, value) {
        if ([AlgorithmType.P256_JWK_PUBLIC, AlgorithmType.RSA_JWK_PUBLIC, AlgorithmType.ED25519_JWK_PUBLIC,
            AlgorithmType.ES256K_JWK_PUBLIC].includes(AlgorithmType[algorithm])) {
            await this.db.put({
                _id: id,
                key: value
            });
        }
    }
    async getImportKey(id) {
        const content = await this.db.get(id);
        return content;
    }
    /**
     * Sets a public key in storage
     * @param id
     * @param algorithm
     * @param value
     */
    async setImportKey(id, value) {
        await this.db.put({
            _id: id,
            key: value
        });
    }
    async createWallet(password, options) {
        let id = Buffer.from(ethers_1.ethers.utils.randomBytes(100)).toString('base64');
        if (options.id) {
            id = options.id;
        }
        let mnemonic = options.mnemonic;
        if (mnemonic) {
            this.ethersWallet = ethers_1.ethers.Wallet.fromMnemonic(mnemonic);
        }
        else {
            this.ethersWallet = ethers_1.ethers.Wallet.createRandom();
            mnemonic = this.ethersWallet.mnemonic;
        }
        this.mnemonic = mnemonic;
        let keystores = new KeyStore();
        let keyExports = new KeyStore();
        // Filecoin
        let keyFil = this.getFilecoinDeriveChild();
        keystores.Filecoin = keyFil;
        // ED25519
        let kp = this.getEd25519();
        keystores.ED25519 = kp.getSecret('hex');
        keyExports.ED25519 = await KeyConvert_1.KeyConvert.getEd25519(kp);
        keyExports.ED25519.ldJsonPublic = await KeyConvert_1.KeyConvert.createLinkedDataJsonFormat(LDCryptoTypes_1.LDCryptoTypes.Ed25519, kp, false);
        // ES256K
        kp = this.getES256K();
        keystores.ES256K = kp.getPrivate('hex');
        keyExports.ES256K = await KeyConvert_1.KeyConvert.getES256K(kp);
        keyExports.ES256K.ldJsonPublic = await KeyConvert_1.KeyConvert.createLinkedDataJsonFormat(LDCryptoTypes_1.LDCryptoTypes.JWK, 
        // @ts-ignore
        { publicJwk: JSON.parse(keyExports.ES256K.ldSuite.publicKeyJwk) }, false);
        // P256
        kp = this.getP256();
        keystores.P256 = kp.getPrivate('hex');
        keyExports.P256 = await KeyConvert_1.KeyConvert.getP256(kp);
        keyExports.P256.ldJsonPublic = await KeyConvert_1.KeyConvert.createLinkedDataJsonFormat(LDCryptoTypes_1.LDCryptoTypes.JWK, 
        // @ts-ignore
        { publicJwk: JSON.parse(keyExports.P256.ldSuite.publicKeyJwk) }, false);
        // RSA
        kp = await Wallet.getRSA256Standalone();
        keystores.RSA = kp.toJSON(true);
        keyExports.RSA = await KeyConvert_1.KeyConvert.getRSA(kp);
        const keystoreMnemonicAsString = await this.ethersWallet.encrypt(password);
        const model = {
            _id: id,
            keypairs: keystores,
            keystoreSeed: keystoreMnemonicAsString,
            mnemonic: mnemonic,
            keypairExports: keyExports,
        };
        await this.db.crypto(password);
        await this.db.put(model);
        this.id = id;
        return this;
    }
    async getPrivateKey(algorithm) {
        const ks = await this.db.get(this.id);
        if (algorithm === 'ED25519') {
            const kp = new elliptic_1.eddsa('ed25519');
            return kp.keyFromSecret(ks.keypairs.ED25519);
        }
        else if (algorithm === 'P256') {
            const kp = new elliptic_1.ec('p256');
            return kp.keyFromPrivate(ks.keypairs.P256);
        }
        else if (algorithm === 'ES256K') {
            const kp = new elliptic_1.ec('secp256k1');
            return kp.keyFromPrivate(ks.keypairs.ES256K);
        }
    }
    async getPrivateKeyExports(algorithm) {
        const ks = await this.db.get(this.id);
        return ks.keypairExports[algorithm];
    }
    async canUse() {
        let ticket = null;
        const init = this.accepted;
        return new Promise((resolve) => {
            ticket = setInterval(() => {
                if (this.accepted !== init) {
                    clearInterval(ticket);
                    resolve(this.accepted);
                    this.accepted = undefined;
                    return;
                }
            }, 1000);
        });
    }
    async signExternal() {
        return this.onSignExternal.toPromise();
    }
    /**
     * Signs with selected algorithm
     * @param algorithm Algorithm
     * @param payload Payload as buffer
     * @param options options
     */
    async sign(algorithm, payload) {
        this.onRequestPassphraseSubscriber.next({ type: 'request_tx', payload, algorithm });
        const canUseIt = await this.canUse();
        let key;
        if (canUseIt) {
            if (algorithm === 'ED25519') {
                key = await this.getPrivateKey(algorithm);
                return [null, key.sign(payload).toHex()];
            }
            else if (algorithm === 'ES256K') {
                key = await this.getPrivateKey(algorithm);
                return [null, key.sign(payload).toHex()];
            }
        }
        return [new Error('invalid_passphrase')];
    }
    /**
     * Signs a JWT for single recipient
     * @param algorithm Algorithm
     * @param payload Payload as buffer
     * @param options options
     */
    async signJWT(algorithm, payload, options) {
        this.onRequestPassphraseSubscriber.next({ type: 'request_tx', payload, algorithm });
        const canUseIt = await this.canUse();
        if (canUseIt) {
            const { pem } = await this.getPrivateKeyExports(algorithm);
            return [null, await JWTService_1.JWTService.sign(pem, payload, options)];
        }
        return [new Error('invalid_passphrase')];
    }
    async signJWTFromPublic(publicKey, payload, options) {
        this.onRequestPassphraseSubscriber.next({ type: 'request_tx', payload });
        const canUseIt = await this.canUse();
        if (canUseIt) {
            return [null, JWTService_1.JWTService.sign(publicKey, payload, options)];
        }
        return [new Error('invalid_passphrase')];
    }
    /**
     * Encrypts JWE
     * @param algorithm Algorithm
     * @param payload Payload as buffer
     * @param overrideWithKey Uses this key instead of current wallet key
     *
     */
    async encryptJWE(algorithm, payload, overrideWithKey) {
        this.onRequestPassphraseSubscriber.next({ type: 'request_tx', payload, algorithm });
        const canUseIt = await this.canUse();
        if (canUseIt) {
            let jwk;
            if (overrideWithKey === null) {
                const keys = await this.getPrivateKeyExports(algorithm);
                jwk = keys.jwk;
            }
            return [null, await JOSEService_1.JOSEService.encrypt([jwk], payload)];
        }
        return [new Error('invalid_passphrase')];
    }
    async decryptJWE(algorithm, payload) {
        this.onRequestPassphraseSubscriber.next({ type: 'request_tx', payload, algorithm });
        const canUseIt = await this.canUse();
        if (canUseIt) {
            const { jwk } = await this.getPrivateKeyExports(algorithm);
            return [null, await node_jose_1.JWE.createDecrypt(await node_jose_1.JWK.asKey(jwk, 'jwk')).decrypt(payload)];
        }
        return [new Error('invalid_passphrase')];
    }
    /**
     * Encrypts JWE with multiple keys
     * @param algorithm
     * @param payload
     */
    async encryptMultipleJWE(keys, algorithm, payload) {
        this.onRequestPassphraseSubscriber.next({ type: 'request_tx', payload, algorithm });
        const canUseIt = await this.canUse();
        if (canUseIt) {
            const { jwk } = await this.getPrivateKeyExports(algorithm);
            return [null, await JOSEService_1.JOSEService.encrypt([jwk, ...keys], payload)];
        }
        return [new Error('invalid_passphrase')];
    }
    /**
    * Generates a mnemonic
    */
    static generateMnemonic() {
        return ethers_1.ethers.Wallet.createRandom().mnemonic;
    }
    async open(id) {
        this.id = id;
        this.onRequestPassphraseSubscriber.next({ type: 'wallet' });
        this.onRequestPassphraseWallet.subscribe(async (p) => {
            if (p.type !== 'ui') {
                this.accepted = p.accepted;
            }
            else {
                try {
                    this.db.crypto(p.passphrase);
                    const ks = await this.db.get(id);
                    this.mnemonic = ks.mnemonic;
                    this.onRequestPassphraseSubscriber.next({ type: 'done' });
                }
                catch (e) {
                    this.onRequestPassphraseSubscriber.next({ type: 'error', error: e });
                }
            }
        });
    }
    extractP12(p12FilePath, password) {
        const { pemKey, pemCertificate, commonName } = p12.getPemFromP12(p12FilePath, password);
        return { pemKey, pemCertificate, commonName };
    }
    /**
     * Derives a new child Wallet
     */
    deriveChild(sequence, derivation = `m/44'/60'/0'/0`) {
        const masterKey = ethers_1.ethers.utils.HDNode.fromMnemonic(this.mnemonic);
        return masterKey.derivePath(`${derivation}/${sequence}`);
    }
    get path() {
        return this.ethersWallet.path;
    }
    get address() {
        return this.ethersWallet.getAddress();
    }
    /**
     * Derives a wallet from a path
     */
    deriveFromPath(path) {
        const node = ethers_1.ethers.utils.HDNode.fromMnemonic(this.mnemonic).derivePath(path);
        return node;
    }
    getFilecoinDeriveChild() {
        return this.deriveFromPath(`m/44'/461'/0/0/1`);
    }
    /**
     * Gets EdDSA key pair
     */
    getEd25519() {
        const ed25519 = new elliptic_1.eddsa('ed25519');
        // const hdkey = HDKey.fromExtendedKey(HDNode.fromMnemonic(this.mnemonic).extendedKey);
        const { key } = ed25519_hd_key_1.getMasterKeyFromSeed(utils_1.mnemonicToSeed(this.mnemonic));
        const keypair = ed25519.keyFromSecret(key);
        return keypair;
    }
    getP256() {
        const p256 = new elliptic_1.ec('p256');
        const keypair = p256.keyFromPrivate(ethers_1.ethers.utils.HDNode.fromMnemonic(this.mnemonic).privateKey);
        return keypair;
    }
    getES256K() {
        const ES256k = new elliptic_1.ec('secp256k1');
        const keypair = ES256k.keyFromPrivate(ethers_1.ethers.utils.HDNode.fromMnemonic(this.mnemonic).privateKey);
        return keypair;
    }
    static getRSA256Standalone(len = 2048) {
        return node_jose_1.JWK.createKey('RSA', len, {
            alg: 'RS256',
            use: 'sig'
        });
    }
}
exports.Wallet = Wallet;
//# sourceMappingURL=Wallet.js.map