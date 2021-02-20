/// <reference types="node" />
import { ec, eddsa } from 'elliptic';
import { ethers } from 'ethers';
import { JWK } from 'node-jose';
import { Subject } from 'rxjs';
export declare type AlgorithmTypeString = keyof typeof AlgorithmType;
export declare enum AlgorithmType {
    RSA = 0,
    ES256K = 1,
    P256 = 2,
    ED25519 = 3,
    BLS = 4,
    P256_JWK_PUBLIC = 5,
    ED25519_JWK_PUBLIC = 6,
    ES256K_JWK_PUBLIC = 7,
    RSA_JWK_PUBLIC = 8,
    RSA_PEM_PUBLIC = 9
}
export declare class WalletOptions {
    password: string;
    mnemonic?: string;
}
export interface KeystoreDbModel {
    _id: any;
    keypairs: KeyStoreModel;
    keystoreSeed: any;
    mnemonic: string;
    keypairExports: KeyStoreModel;
    publicKeys?: any;
}
export interface KeyStoreModel {
    BLS?: any;
    ES256K: any;
    P256: any;
    RSA: any;
    ED25519: any;
    Filecoin: any;
    Vechain?: any;
    Polkadot?: any;
}
export declare class KeyStore implements KeyStoreModel {
    ED25519: any;
    ES256K: any;
    P256: any;
    RSA: any;
    BLS: any;
    Filecoin: any;
    Vechain: any;
    Polkadot: any;
    constructor();
}
declare type FilecoinSignTypes = 'filecoin' | 'lotus';
export declare class Wallet {
    id: string;
    onRequestPassphraseSubscriber: Subject<any>;
    onRequestPassphraseWallet: Subject<any>;
    onSignExternal: Subject<any>;
    private db;
    ethersWallet: any;
    mnemonic: any;
    accepted: any;
    constructor();
    /**
     * Verifies a filecoin signed transaction
     * @param signature a filecoin signature
     * @param cborContent a filecoint raw transaction
     */
    verifyFilecoinSignature(signature: string, cborContent: string): Promise<boolean>;
    /**
     * Signs a filecoin transaction
     * @param transaction a filecoin transaction
     * @param signer Sets the filecoin or lotus signer
     */
    signFilecoinTransaction(transaction: any, signer: FilecoinSignTypes): Promise<[Error, any?]>;
    /**
     * Gets a public key from storage
     * @param id
     * @param algorithm
     */
    getPublicKey(id: string): Promise<any>;
    /**
     * Sets a public key in storage
     * @param id
     * @param algorithm
     * @param value
     */
    setPublicKey(id: string, algorithm: AlgorithmTypeString, value: object): Promise<void>;
    getImportKey(id: string): Promise<any>;
    /**
     * Sets a public key in storage
     * @param id
     * @param algorithm
     * @param value
     */
    setImportKey(id: string, value: object): Promise<void>;
    createWallet(password: string, options: any): Promise<this>;
    getPrivateKey(algorithm: AlgorithmTypeString): Promise<ec.KeyPair | eddsa.KeyPair>;
    getPrivateKeyExports(algorithm: AlgorithmTypeString): Promise<any>;
    canUse(): Promise<unknown>;
    signExternal(): Promise<any>;
    /**
     * Signs with selected algorithm
     * @param algorithm Algorithm
     * @param payload Payload as buffer
     * @param options options
     */
    sign(algorithm: AlgorithmTypeString, payload: Buffer): Promise<[Error, any?]>;
    /**
     * Signs a JWT for single recipient
     * @param algorithm Algorithm
     * @param payload Payload as buffer
     * @param options options
     */
    signJWT(algorithm: AlgorithmTypeString, payload: any, options: any): Promise<[Error, any?]>;
    signJWTFromPublic(publicKey: any, payload: any, options: any): Promise<[Error, any?]>;
    /**
     * Encrypts JWE
     * @param algorithm Algorithm
     * @param payload Payload as buffer
     * @param overrideWithKey Uses this key instead of current wallet key
     *
     */
    encryptJWE(algorithm: AlgorithmTypeString, payload: any, overrideWithKey: any): Promise<[Error, any?]>;
    decryptJWE(algorithm: AlgorithmTypeString, payload: any): Promise<[Error, any?]>;
    /**
     * Encrypts JWE with multiple keys
     * @param algorithm
     * @param payload
     */
    encryptMultipleJWE(keys: any[], algorithm: AlgorithmTypeString, payload: any): Promise<[Error, any?]>;
    /**
    * Generates a mnemonic
    */
    static generateMnemonic(): ethers.utils.Mnemonic;
    open(id: string): Promise<void>;
    extractP12(p12FilePath: string, password: string): {
        pemKey: string;
        pemCertificate: string;
        commonName: any;
    };
    /**
     * Derives a new child Wallet
     */
    deriveChild(sequence: number, derivation?: string): any;
    get path(): any;
    get address(): any;
    /**
     * Derives a wallet from a path
     */
    deriveFromPath(path: string): any;
    getFilecoinDeriveChild(): any;
    /**
     * Gets EdDSA key pair
     */
    getEd25519(): eddsa.KeyPair;
    getP256(): ec.KeyPair;
    getES256K(): ec.KeyPair;
    static getRSA256Standalone(len?: number): Promise<JWK.RSAKey>;
}
export {};
