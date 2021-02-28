"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Wallet = exports.KeyStore = exports.WalletOptions = exports.AlgorithmType = void 0;
const tslib_1 = require("tslib");
const pouchdb_1 = tslib_1.__importDefault(require("pouchdb"));
const elliptic_1 = require("elliptic");
const ethers_1 = require("ethers");
const ed25519_hd_key_1 = require("ed25519-hd-key");
const class_validator_1 = require("class-validator");
const JOSEService_1 = require("./JOSEService");
const node_jose_1 = require("node-jose");
const JWTService_1 = require("./JWTService");
const KeyConvert_1 = require("./KeyConvert");
const LDCryptoTypes_1 = require("./LDCryptoTypes");
const rxjs_1 = require("rxjs");
const utils_1 = require("ethers/lib/utils");
const web3_1 = tslib_1.__importDefault(require("web3"));
const DIDManager_1 = require("../3id/DIDManager");
const did_jwt_1 = require("did-jwt");
const eth_crypto_1 = tslib_1.__importDefault(require("eth-crypto"));
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
    constructor() { }
}
exports.KeyStore = KeyStore;
class Wallet {
    constructor() {
        this.DB_NAME = 'xdv:universal:wallet';
        this.onRequestPassphraseSubscriber = new rxjs_1.Subject();
        this.onRequestPassphraseWallet = new rxjs_1.Subject();
        this.onSignExternal = new rxjs_1.Subject();
        this.db = new pouchdb_1.default(this.DB_NAME);
        pouchdb_1.default.plugin(require('crypto-pouch'));
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
    async getUniversalWalletKey(alg) {
        const jwk = node_jose_1.JWK.createKey('oct', 256, {
            alg,
        });
    }
    /**
     * Creates an universal wallet for ES256K
     * @param options { passphrase, walletid, registry, rpcUrl }
     */
    static async createES256K(options) {
        let wallet = new Wallet();
        let ks;
        if (options.passphrase && options.walletId) {
            wallet.db.open(options.passphrase);
            ks = await wallet.db.get(options.walletId);
            //open an existing wallet
        }
        else if (options.passphrase && !options.walletId) {
            wallet = await wallet.createAccount(options);
            ks = (await wallet.getAccount()).keystores.find((w) => w._id === options.walletId);
        }
        const kp = new elliptic_1.ec('secp256k1');
        const kpInstance = kp.keyFromPrivate(ks.keypairs.ES256K);
        const didManager = new DIDManager_1.DIDManager();
        const address = did_jwt_1.toEthereumAddress(kpInstance.getPublic('hex'));
        const encrypt = async (pub, message) => {
            const data = await eth_crypto_1.default.encryptWithPublicKey(pub.replace('0x', ''), message);
            return eth_crypto_1.default.cipher.stringify(data);
        };
        const decrypt = async (cipher) => {
            const data = await eth_crypto_1.default.decryptWithPrivateKey(ks.keypairs.ES256K, eth_crypto_1.default.cipher.parse(cipher));
            return data;
        };
        // Buffer.from(pub, 'hex')
        const did = didManager.createEthrDID(address, kpInstance, options.registry, options.rpcUrl);
        return {
            did,
            secureMessage: {
                encrypt,
                decrypt,
            },
            address,
            privateKey: kpInstance.getPrivate('hex'),
            publicKey: kpInstance.getPublic('hex'),
        };
    }
    /**
     * Creates an universal wallet for Ed25519
     * @param nodeurl EVM Node
     * @param options { passphrase, walletid }
     */
    static async create3IDEd25519(options) {
        let wallet = new Wallet();
        let ks;
        if (options.passphrase && options.walletId) {
            wallet.db.open(options.passphrase);
            ks = await wallet.db.get(options.walletId);
            //open an existing wallet
        }
        else if (options.passphrase && !options.walletId) {
            wallet = await wallet.createAccount(options);
            ks = (await wallet.getAccount()).keystores.find((w) => w._id === options.walletId);
        }
        const kp = new elliptic_1.eddsa('ed25519');
        const kpInstance = kp.keyFromSecret(ks.keypairs.ED25519);
        const didManager = new DIDManager_1.DIDManager();
        const { did, getIssuer } = await didManager.create3ID_Ed25519(kpInstance);
        return {
            did,
            getIssuer,
            privateKey: kpInstance.getSecret(),
            publicKey: kpInstance.getPublic(),
        };
    }
    /**
     * Creates an universal wallet  for Web3 Providers
     * @param options { passphrase, walletid, registry, rpcUrl }
     */
    static async createWeb3Provider(options) {
        //Options will have 2 variables (wallet id and passphrase)
        let web3;
        let wallet = new Wallet();
        let ks;
        if (options.passphrase && options.walletId) {
            wallet.db.open(options.passphrase);
            web3 = new web3_1.default(options.rpcUrl);
            ks = await wallet.db.get(options.walletId);
            //open an existing wallet
        }
        else if (options.passphrase && !options.walletId) {
            wallet = await wallet.createAccount(options);
            ks = (await wallet.getAccount()).keystores.find((w) => w._id === options.walletId);
            web3 = new web3_1.default(options.rpcUrl);
        }
        const privateKey = '0x' + ks.keypairs.ES256K;
        web3.eth.accounts.wallet.add(privateKey);
        const address = web3.eth.accounts.privateKeyToAccount(privateKey).address;
        web3.defaultAccount = address;
        const didManager = new DIDManager_1.DIDManager();
        const ES256k = new elliptic_1.ec('secp256k1');
        const encrypt = async (pub, message) => {
            const data = await eth_crypto_1.default.encryptWithPublicKey(pub.replace('0x', ''), message);
            return eth_crypto_1.default.cipher.stringify(data);
        };
        const decrypt = async (cipher) => {
            const data = await eth_crypto_1.default.decryptWithPrivateKey(ks.keypairs.ES256K, eth_crypto_1.default.cipher.parse(cipher));
            return data;
        };
        const { did, issuer } = await didManager.create3IDWeb3(address, ES256k.keyFromPrivate(ks.keypairs.ES256K), web3, options.registry);
        return {
            did,
            secureMessage: {
                encrypt,
                decrypt,
            },
            publicKey: ES256k.keyFromPrivate(ks.keypairs.ES256K).getPublic(),
            issuer,
            web3,
            address,
        };
    }
    /**
     * Sets a public key in storage
     * @param id
     * @param algorithm
     * @param value
     */
    async setPublicKey(id, algorithm, value) {
        if ([
            AlgorithmType.P256_JWK_PUBLIC,
            AlgorithmType.RSA_JWK_PUBLIC,
            AlgorithmType.ED25519_JWK_PUBLIC,
            AlgorithmType.ES256K_JWK_PUBLIC,
        ].includes(AlgorithmType[algorithm])) {
            await this.db.put({
                _id: id,
                key: value,
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
            key: value,
        });
    }
    /**
     * Creates an account and a set of ES256K and ED25519 Wallets
     * @param options
     */
    async createAccount(options) {
        let a;
        try {
            a = await this.db.get('xdv:account');
        }
        catch (e) {
            // continue
        }
        if (a && a._rev)
            throw new Error('Account already created, please use addWallet to create new keys');
        let id = Buffer.from(ethers_1.ethers.utils.randomBytes(100)).toString('base64');
        if (options.walletId) {
            id = options.walletId;
        }
        let mnemonic = options.mnemonic;
        let ethersWallet;
        if (mnemonic) {
            ethersWallet = ethers_1.ethers.Wallet.fromMnemonic(mnemonic);
        }
        else {
            ethersWallet = ethers_1.ethers.Wallet.createRandom();
            mnemonic = ethersWallet.mnemonic.phrase;
        }
        let keystores = new KeyStore();
        let keyExports = new KeyStore();
        // ED25519
        let kp = this.getEd25519(mnemonic);
        keystores.ED25519 = kp.getSecret('hex');
        keyExports.ED25519 = await KeyConvert_1.KeyConvert.getEd25519(kp);
        keyExports.ED25519.ldJsonPublic = await KeyConvert_1.KeyConvert.createLinkedDataJsonFormat(LDCryptoTypes_1.LDCryptoTypes.Ed25519, kp, false);
        // ES256K
        const kpec = this.getES256K(mnemonic);
        keystores.ES256K = kpec.getPrivate('hex');
        keyExports.ES256K = await KeyConvert_1.KeyConvert.getES256K(kpec);
        keyExports.ES256K.ldJsonPublic = await KeyConvert_1.KeyConvert.createLinkedDataJsonFormat(LDCryptoTypes_1.LDCryptoTypes.JWK, 
        // @ts-ignore
        { publicJwk: JSON.parse(keyExports.ES256K.ldSuite.publicKeyJwk) }, false);
        const keystoreMnemonicAsString = await ethersWallet.encrypt(options.passphrase);
        const keystore = {
            _id: id,
            keypairs: keystores,
            keystoreSeed: keystoreMnemonicAsString,
            mnemonic: mnemonic,
            keypairExports: keyExports,
        };
        const account = {
            keystores: [keystore],
            currentKeystoreId: id,
            isActive: true,
            _id: 'xdv:account',
            attributes: [],
            isLocked: true,
            description: options.accountName,
            id: new Date().getTime().toFixed(),
        };
        // await this.db.crypto(options.passphrase)
        await this.db.put(account);
        return this;
    }
    /**
     * Adds a set of ES256K and ED25519 Wallets
     * @param options
     */
    async addWallet(options) {
        let account;
        try {
            account = await this.db.get('xdv:account');
        }
        catch (e) {
            throw new Error('No account created');
        }
        let id = Buffer.from(ethers_1.ethers.utils.randomBytes(100)).toString('base64');
        if (options.walletId) {
            id = options.walletId;
        }
        let mnemonic = options.mnemonic;
        let ethersWallet;
        if (mnemonic) {
            ethersWallet = ethers_1.ethers.Wallet.fromMnemonic(mnemonic);
        }
        else {
            ethersWallet = ethers_1.ethers.Wallet.createRandom();
            mnemonic = ethersWallet.mnemonic.phrase;
        }
        let keystores = new KeyStore();
        let keyExports = new KeyStore();
        // ED25519
        let kp = this.getEd25519(mnemonic);
        keystores.ED25519 = kp.getSecret('hex');
        keyExports.ED25519 = await KeyConvert_1.KeyConvert.getEd25519(kp);
        keyExports.ED25519.ldJsonPublic = await KeyConvert_1.KeyConvert.createLinkedDataJsonFormat(LDCryptoTypes_1.LDCryptoTypes.Ed25519, kp, false);
        // ES256K
        const kpec = this.getES256K(mnemonic);
        keystores.ES256K = kpec.getPrivate('hex');
        keyExports.ES256K = await KeyConvert_1.KeyConvert.getES256K(kpec);
        keyExports.ES256K.ldJsonPublic = await KeyConvert_1.KeyConvert.createLinkedDataJsonFormat(LDCryptoTypes_1.LDCryptoTypes.JWK, 
        // @ts-ignore
        { publicJwk: JSON.parse(keyExports.ES256K.ldSuite.publicKeyJwk) }, false);
        const keystoreMnemonicAsString = await ethersWallet.encrypt(options.passphrase);
        const keystore = {
            _id: id,
            keypairs: keystores,
            keystoreSeed: keystoreMnemonicAsString,
            mnemonic: mnemonic,
            keypairExports: keyExports,
        };
        account.keystores.push(keystore);
        account.isActive = true;
        account.isLocked = true;
        account.currentKeystoreId = id;
        await this.db.crypto(options.passphrase);
        await this.db.put(account);
        return this;
    }
    async getPrivateKey(algorithm, keystoreId) {
        const ks = (await this.getAccount()).keystores.find((w) => w._id === keystoreId);
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
    async getPrivateKeyExports(algorithm, keystoreId) {
        const ks = (await this.getAccount()).keystores.find((w) => w._id === keystoreId);
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
    /**
     * Signs with selected algorithm
     * @param algorithm Algorithm
     * @param payload Payload as buffer
     * @param options options
     */
    async sign(algorithm, keystoreId, payload) {
        this.onRequestPassphraseSubscriber.next({
            type: 'request_tx',
            payload,
            algorithm,
        });
        const canUseIt = await this.canUse();
        let key;
        if (canUseIt) {
            if (algorithm === 'ED25519') {
                key = await this.getPrivateKey(algorithm, keystoreId);
                return [null, key.sign(payload).toHex()];
            }
            else if (algorithm === 'ES256K') {
                key = await this.getPrivateKey(algorithm, keystoreId);
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
    async signJWT(algorithm, keystoreId, payload, options) {
        this.onRequestPassphraseSubscriber.next({
            type: 'request_tx',
            payload,
            algorithm,
        });
        const canUseIt = await this.canUse();
        if (canUseIt) {
            const { pem } = await this.getPrivateKeyExports(algorithm, keystoreId);
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
    async encryptJWE(algorithm, keystoreId, payload, overrideWithKey) {
        this.onRequestPassphraseSubscriber.next({
            type: 'request_tx',
            payload,
            algorithm,
        });
        const canUseIt = await this.canUse();
        if (canUseIt) {
            let jwk;
            if (overrideWithKey === null) {
                const keys = await this.getPrivateKeyExports(algorithm, keystoreId);
                jwk = keys.jwk;
            }
            // @ts-ignore
            return [null, await JOSEService_1.JOSEService.encrypt([jwk], payload)];
        }
        return [new Error('invalid_passphrase')];
    }
    async decryptJWE(algorithm, keystoreId, payload) {
        this.onRequestPassphraseSubscriber.next({
            type: 'request_tx',
            payload,
            algorithm,
        });
        const canUseIt = await this.canUse();
        if (canUseIt) {
            const { jwk } = await this.getPrivateKeyExports(algorithm, keystoreId);
            return [
                null,
                await node_jose_1.JWE.createDecrypt(await node_jose_1.JWK.asKey(jwk, 'jwk')).decrypt(payload),
            ];
        }
        return [new Error('invalid_passphrase')];
    }
    /**
     * Generates a mnemonic
     */
    static generateMnemonic() {
        return ethers_1.ethers.Wallet.createRandom().mnemonic;
    }
    async unlockKeystore(id) {
        this.onRequestPassphraseSubscriber.next({ type: 'wallet', value: id });
        this.onRequestPassphraseWallet.subscribe(async (p) => {
            if (p.type !== 'ui') {
                this.accepted = p.accepted;
            }
            else {
                try {
                    this.db.crypto(p.passphrase);
                    this.onRequestPassphraseSubscriber.next({ type: 'done', value: id });
                }
                catch (e) {
                    this.onRequestPassphraseSubscriber.next({ type: 'error', error: e });
                }
            }
        });
    }
    /**
     * Derives a wallet from a path
     */
    deriveFromPath(mnemonic, path) {
        const node = ethers_1.ethers.utils.HDNode.fromMnemonic(mnemonic).derivePath(path);
        return node;
    }
    /**
     * Gets EdDSA key pair
     */
    getEd25519(mnemonic) {
        const ed25519 = new elliptic_1.eddsa('ed25519');
        // const hdkey = HDKey.fromExtendedKey(HDNode.fromMnemonic(this.mnemonic).extendedKey);
        const { key } = ed25519_hd_key_1.getMasterKeyFromSeed(utils_1.mnemonicToSeed(mnemonic));
        const keypair = ed25519.keyFromSecret(key);
        return keypair;
    }
    getES256K(mnemonic) {
        const ES256k = new elliptic_1.ec('secp256k1');
        const keypair = ES256k.keyFromPrivate(ethers_1.ethers.utils.HDNode.fromMnemonic(mnemonic).privateKey);
        return keypair;
    }
    /**
     * Gets keystore from session db
     */
    async getAccount() {
        try {
            const item = await this.db.get('xdv:account');
            return item;
        }
        catch (e) {
            return null;
        }
    }
    /**
     * Sets a keystore index, if keystore is diff, then clears lock (lock set to false)
     * @param id
     */
    async setAccountLock(lock) {
        let accountInstance;
        try {
            accountInstance = await this.db.get('xdv:account');
            accountInstance.isLocked = lock;
            return this.db.put(accountInstance);
        }
        catch (e) {
            throw e;
        }
    }
    async setCurrentKeystore(id) {
        let accountInstance;
        try {
            accountInstance = await this.db.get('xdv:account');
            accountInstance.currentKeystoreId = id;
            return this.db.put(accountInstance);
        }
        catch (e) {
            throw e;
        }
    }
}
exports.Wallet = Wallet;
//# sourceMappingURL=Wallet.js.map