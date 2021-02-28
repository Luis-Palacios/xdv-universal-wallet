/// <reference types="node" />
import EthrDID from 'ethr-did';
import { ec, eddsa } from 'elliptic';
import { ethers } from 'ethers';
import { Subject } from 'rxjs';
import Web3 from 'web3';
import { DID } from 'dids';
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
export interface XDVUniversalProvider {
    did: DID & EthrDID;
    secureMessage: any;
    privateKey: any;
    getIssuer: Function;
    issuer?: EthrDID;
    id: string;
    web3?: Web3;
    address?: string;
    publicKey: any;
}
export interface ICreateOrLoadWalletProps {
    walletId?: string;
    passphrase: string;
    registry?: string;
    rpcUrl?: string;
    mnemonic?: string;
    accountName: string;
}
export interface KeyStoreModel {
    ES256K: any;
    P256: any;
    ED25519: any;
}
export interface KeystoreDbModel {
    _id: any;
    keypairs: KeyStoreModel;
    keystoreSeed: any;
    mnemonic: string;
    path?: string;
    keypairExports: KeyStoreModel;
    publicKeys?: any;
}
export declare class KeyStore implements KeyStoreModel {
    ED25519: any;
    ES256K: any;
    P256: any;
    constructor();
}
export interface Account {
    _id: string;
    id: string;
    timestamp: Date;
    isActive: boolean;
    isLocked: boolean;
    description: string;
    attributes: string[];
    currentKeystoreId: string;
    keystores: KeystoreDbModel[];
}
export declare class Wallet {
    private readonly DB_NAME;
    onRequestPassphraseSubscriber: Subject<any>;
    onRequestPassphraseWallet: Subject<any>;
    onSignExternal: Subject<any>;
    protected db: any;
    accepted: any;
    constructor();
    /**
     * Gets a public key from storage
     * @param id
     * @param algorithm
     */
    getPublicKey(id: string): Promise<any>;
    getUniversalWalletKey(alg: string): Promise<void>;
    /**
     * Creates an universal wallet for ES256K
     * @param options { passphrase, walletid, registry, rpcUrl }
     */
    static createES256K(options: ICreateOrLoadWalletProps): Promise<XDVUniversalProvider>;
    /**
     * Creates an universal wallet for Ed25519
     * @param nodeurl EVM Node
     * @param options { passphrase, walletid }
     */
    static create3IDEd25519(options: ICreateOrLoadWalletProps): Promise<XDVUniversalProvider>;
    /**
     * Creates an universal wallet  for Web3 Providers
     * @param options { passphrase, walletid, registry, rpcUrl }
     */
    static createWeb3Provider(options: ICreateOrLoadWalletProps): Promise<XDVUniversalProvider>;
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
    /**
     * Creates an account and a set of ES256K and ED25519 Wallets
     * @param options
     */
    createAccount(options: ICreateOrLoadWalletProps): Promise<this>;
    /**
     * Adds a set of ES256K and ED25519 Wallets
     * @param options
     */
    addWallet(options: ICreateOrLoadWalletProps): Promise<this>;
    protected getPrivateKey(algorithm: AlgorithmTypeString, keystoreId: string): Promise<ec.KeyPair | eddsa.KeyPair>;
    protected getPrivateKeyExports(algorithm: AlgorithmTypeString, keystoreId: string): Promise<any>;
    canUse(): Promise<unknown>;
    /**
     * Signs with selected algorithm
     * @param algorithm Algorithm
     * @param payload Payload as buffer
     * @param options options
     */
    sign(algorithm: AlgorithmTypeString, keystoreId: string, payload: Buffer): Promise<[Error, any?]>;
    /**
     * Signs a JWT for single recipient
     * @param algorithm Algorithm
     * @param payload Payload as buffer
     * @param options options
     */
    signJWT(algorithm: AlgorithmTypeString, keystoreId: string, payload: any, options: any): Promise<[Error, any?]>;
    signJWTFromPublic(publicKey: any, payload: any, options: any): Promise<[Error, any?]>;
    /**
     * Encrypts JWE
     * @param algorithm Algorithm
     * @param payload Payload as buffer
     * @param overrideWithKey Uses this key instead of current wallet key
     *
     */
    encryptJWE(algorithm: AlgorithmTypeString, keystoreId: string, payload: any, overrideWithKey: any): Promise<[Error, any?]>;
    decryptJWE(algorithm: AlgorithmTypeString, keystoreId: string, payload: any): Promise<[Error, any?]>;
    /**
     * Generates a mnemonic
     */
    static generateMnemonic(): ethers.utils.Mnemonic;
    unlockKeystore(id: string): Promise<void>;
    /**
     * Derives a wallet from a path
     */
    deriveFromPath(mnemonic: string, path: string): any;
    /**
     * Gets EdDSA key pair
     */
    getEd25519(mnemonic: string): eddsa.KeyPair;
    getES256K(mnemonic: string): ec.KeyPair;
    /**
     * Gets keystore from session db
     */
    getAccount(): Promise<Account>;
    /**
     * Sets a keystore index, if keystore is diff, then clears lock (lock set to false)
     * @param id
     */
    setAccountLock(lock: boolean): Promise<any>;
    setCurrentKeystore(id: string): Promise<any>;
}
