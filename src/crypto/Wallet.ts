import EthrDID from 'ethr-did'
import PouchDB from 'pouchdb'
import { ec, eddsa } from 'elliptic'
import { BigNumber, ethers } from 'ethers'
import { getMasterKeyFromSeed } from 'ed25519-hd-key'
import { IsDefined, IsOptional, IsString } from 'class-validator'
import { JOSEService } from './JOSEService'
import { JWE, JWK } from 'node-jose'
import { JWTService } from './JWTService'
import { KeyConvert } from './KeyConvert'
import { LDCryptoTypes } from './LDCryptoTypes'
import { from, Subject } from 'rxjs'
import { mnemonicToSeed } from 'ethers/lib/utils'
import Web3 from 'web3'
import { DIDManager } from '../3id/DIDManager'
import { DID } from 'dids'
import * as ed from 'noble-ed25519'
import { toEthereumAddress } from 'did-jwt'
import EthCrypto from 'eth-crypto'
import { stringToBytes } from 'did-jwt/lib/util'

export type AlgorithmTypeString = keyof typeof AlgorithmType
export enum AlgorithmType {
  RSA,
  ES256K,
  P256,
  ED25519,
  BLS,
  P256_JWK_PUBLIC,
  ED25519_JWK_PUBLIC,
  ES256K_JWK_PUBLIC,
  RSA_JWK_PUBLIC,
  RSA_PEM_PUBLIC,
}

export class WalletOptions {
  @IsString()
  @IsDefined()
  password: string

  @IsOptional()
  @IsString()
  mnemonic?: string
}
export interface XDVUniversalProvider {
  did: DID & EthrDID
  secureMessage: any
  privateKey: any
  getIssuer: Function
  issuer?: EthrDID
  id: string
  web3?: Web3
  address?: string
  publicKey: any
}

export interface ICreateOrLoadWalletProps {
  walletId?: string
  passphrase: string
  registry?: string
  rpcUrl?: string
  mnemonic?: string
  accountName: string
}

export interface KeyStoreModel {
  ES256K: any
  P256: any
  ED25519: any
}

export interface KeystoreDbModel {
  _id: any
  keypairs: KeyStoreModel
  keystoreSeed: any
  mnemonic: string
  path?: string
  keypairExports: KeyStoreModel
  publicKeys?: any
}

export class KeyStore implements KeyStoreModel {
  public ED25519: any
  public ES256K: any
  public P256: any
  constructor() {}
}

// Main data repository
export interface Account {
  _id: string
  id: string
  timestamp: Date
  isActive: boolean
  isLocked: boolean
  description: string
  attributes: string[]
  currentKeystoreId: string
  keystores: KeystoreDbModel[]
}

export class Wallet {
  private readonly DB_NAME = 'xdv:universal:wallet'
  public onRequestPassphraseSubscriber: Subject<any> = new Subject<any>()
  public onRequestPassphraseWallet: Subject<any> = new Subject<any>()
  public onSignExternal: Subject<any> = new Subject<{
    isEnabled: boolean
    signature: string | Buffer
  }>()
  protected db = new PouchDB(this.DB_NAME)
  accepted: any

  constructor() {
    PouchDB.plugin(require('crypto-pouch'))
  }

  /**
   * Gets a public key from storage
   * @param id
   * @param algorithm
   */
  public async getPublicKey(id: string) {
    const content = await this.db.get(id)
    return await JWK.asKey(JSON.parse(content.key), 'jwk')
  }

  public async getUniversalWalletKey(alg: string) {
    const jwk = JWK.createKey('oct', 256, {
      alg,
    })
  }

  /**
   * Creates an universal wallet for ES256K
   * @param options { passphrase, walletid, registry, rpcUrl }
   */
  static async createES256K(options: ICreateOrLoadWalletProps) {
    let wallet = new Wallet()
    let ks

    if (options.passphrase && options.walletId) {
      wallet.db.open(options.passphrase)
      ks = await wallet.db.get(options.walletId)

      //open an existing wallet
    } else if (options.passphrase && !options.walletId) {
      wallet = await wallet.createAccount(options)
      ks = (await wallet.getAccount()).keystores.find(
        (w) => w._id === options.walletId,
      )
    }
    const kp = new ec('secp256k1')
    const kpInstance = kp.keyFromPrivate(ks.keypairs.ES256K) as ec.KeyPair
    const didManager = new DIDManager()
    const address = toEthereumAddress(kpInstance.getPublic('hex'))

    const encrypt = async (pub, message) => {
      const data: any = await EthCrypto.encryptWithPublicKey(
        pub.replace('0x', ''),
        message,
      )

      return EthCrypto.cipher.stringify(data)
    }

    const decrypt = async (cipher) => {
      const data: any = await EthCrypto.decryptWithPrivateKey(
        ks.keypairs.ES256K,
        EthCrypto.cipher.parse(cipher),
      )

      return data
    }

    // Buffer.from(pub, 'hex')
    const did = didManager.createEthrDID(
      address,
      kpInstance,
      options.registry,
      options.rpcUrl,
    )

    return ({
      did,
      secureMessage: {
        encrypt,
        decrypt,
      },
      address,
      privateKey: kpInstance.getPrivate('hex'),
      publicKey: kpInstance.getPublic('hex'),
    } as unknown) as XDVUniversalProvider
  }
  /**
   * Creates an universal wallet for Ed25519
   * @param nodeurl EVM Node
   * @param options { passphrase, walletid }
   */
  static async create3IDEd25519(options: ICreateOrLoadWalletProps) {
    let wallet = new Wallet()
    let ks

    if (options.passphrase && options.walletId) {
      wallet.db.open(options.passphrase)
      ks = await wallet.db.get(options.walletId)

      //open an existing wallet
    } else if (options.passphrase && !options.walletId) {
      wallet = await wallet.createAccount(options)
      ks = (await wallet.getAccount()).keystores.find(
        (w) => w._id === options.walletId,
      )
    }
    const kp = new eddsa('ed25519')
    const kpInstance = kp.keyFromSecret(ks.keypairs.ED25519) as eddsa.KeyPair
    const didManager = new DIDManager()
    const { did, getIssuer } = await didManager.create3ID_Ed25519(kpInstance)

    return ({
      did,
      getIssuer,
      privateKey: kpInstance.getSecret(),
      publicKey: kpInstance.getPublic(),
    } as unknown) as XDVUniversalProvider
  }

  /**
   * Creates an universal wallet  for Web3 Providers
   * @param options { passphrase, walletid, registry, rpcUrl }
   */
  static async createWeb3Provider(options: ICreateOrLoadWalletProps) {
    //Options will have 2 variables (wallet id and passphrase)
    let web3
    let wallet = new Wallet()
    let ks

    if (options.passphrase && options.walletId) {
      wallet.db.open(options.passphrase)
      web3 = new Web3(options.rpcUrl)
      ks = await wallet.db.get(options.walletId)

      //open an existing wallet
    } else if (options.passphrase && !options.walletId) {
      wallet = await wallet.createAccount(options)
      ks = (await wallet.getAccount()).keystores.find(
        (w) => w._id === options.walletId,
      )
      web3 = new Web3(options.rpcUrl)
    }
    const privateKey = '0x' + ks.keypairs.ES256K
    web3.eth.accounts.wallet.add(privateKey)
    const address = web3.eth.accounts.privateKeyToAccount(privateKey).address
    web3.defaultAccount = address
    const didManager = new DIDManager()
    const ES256k = new ec('secp256k1')

    const encrypt = async (pub, message) => {
      const data: any = await EthCrypto.encryptWithPublicKey(
        pub.replace('0x', ''),
        message,
      )

      return EthCrypto.cipher.stringify(data)
    }

    const decrypt = async (cipher) => {
      const data: any = await EthCrypto.decryptWithPrivateKey(
        ks.keypairs.ES256K,
        EthCrypto.cipher.parse(cipher),
      )

      return data
    }
    const { did, issuer } = await didManager.create3IDWeb3(
      address,
      ES256k.keyFromPrivate(ks.keypairs.ES256K),
      web3,
      options.registry,
    )

    return ({
      did,
      secureMessage: {
        encrypt,
        decrypt,
      },
      publicKey: ES256k.keyFromPrivate(ks.keypairs.ES256K).getPublic(),
      issuer,
      web3,
      address,
    } as unknown) as XDVUniversalProvider
  }

  /**
   * Sets a public key in storage
   * @param id
   * @param algorithm
   * @param value
   */
  public async setPublicKey(
    id: string,
    algorithm: AlgorithmTypeString,
    value: object,
  ) {
    if (
      [
        AlgorithmType.P256_JWK_PUBLIC,
        AlgorithmType.RSA_JWK_PUBLIC,
        AlgorithmType.ED25519_JWK_PUBLIC,
        AlgorithmType.ES256K_JWK_PUBLIC,
      ].includes(AlgorithmType[algorithm])
    ) {
      await this.db.put({
        _id: id,
        key: value,
      })
    }
  }

  public async getImportKey(id: string) {
    const content = await this.db.get(id)
    return content
  }

  /**
   * Sets a public key in storage
   * @param id
   * @param algorithm
   * @param value
   */
  public async setImportKey(id: string, value: object) {
    await this.db.put({
      _id: id,
      key: value,
    })
  }

  /**
   * Creates an account and a set of ES256K and ED25519 Wallets
   * @param options
   */
  public async createAccount(options: ICreateOrLoadWalletProps) {
    let a
    try {
       a = await this.db.get('xdv:account')

    } catch (e) {
      // continue
    }


    if (a && a._rev)
    throw new Error(
      'Account already created, please use addWallet to create new keys',
    )

    let id = Buffer.from(ethers.utils.randomBytes(100)).toString('base64')
    if (options.walletId) {
      id = options.walletId
    }
    let mnemonic = options.mnemonic
    let ethersWallet
    if (mnemonic) {
      ethersWallet = ethers.Wallet.fromMnemonic(mnemonic)
    } else {
      ethersWallet = ethers.Wallet.createRandom()
      mnemonic = ethersWallet.mnemonic.phrase
    }

    let keystores: KeyStoreModel = new KeyStore()
    let keyExports: KeyStoreModel = new KeyStore()

    // ED25519
    let kp = this.getEd25519(mnemonic)
    keystores.ED25519 = kp.getSecret('hex')
    keyExports.ED25519 = await KeyConvert.getEd25519(kp)
    keyExports.ED25519.ldJsonPublic = await KeyConvert.createLinkedDataJsonFormat(
      LDCryptoTypes.Ed25519,
      kp as any,
      false,
    )

    // ES256K
    const kpec = this.getES256K(mnemonic) as ec.KeyPair
    keystores.ES256K = kpec.getPrivate('hex')
    keyExports.ES256K = await KeyConvert.getES256K(kpec)
    keyExports.ES256K.ldJsonPublic = await KeyConvert.createLinkedDataJsonFormat(
      LDCryptoTypes.JWK,
      // @ts-ignore
      { publicJwk: JSON.parse(keyExports.ES256K.ldSuite.publicKeyJwk) },
      false,
    )

    const keystoreMnemonicAsString = await ethersWallet.encrypt(
      options.passphrase,
    )

    const keystore: KeystoreDbModel = {
      _id: id,
      keypairs: keystores,
      keystoreSeed: keystoreMnemonicAsString,
      mnemonic: mnemonic,
      keypairExports: keyExports,
    }

    const account = {
      keystores: [keystore],
      currentKeystoreId: id,
      isActive: true,
      _id: 'xdv:account',
      attributes: [],
      isLocked: true,
      description: options.accountName,
      id: new Date().getTime().toFixed(),
    } as Account

    // await this.db.crypto(options.passphrase)
    await this.db.put(account)

    return this
  }

  /**
   * Adds a set of ES256K and ED25519 Wallets
   * @param options
   */
  public async addWallet(options: ICreateOrLoadWalletProps) {
    let account: Account
    try {
      account = await this.db.get('xdv:account')
    } catch (e) {
      throw new Error('No account created')
    }
    let id = Buffer.from(ethers.utils.randomBytes(100)).toString('base64')
    if (options.walletId) {
      id = options.walletId
    }
    let mnemonic = options.mnemonic
    let ethersWallet
    if (mnemonic) {
      ethersWallet = ethers.Wallet.fromMnemonic(mnemonic)
    } else {
      ethersWallet = ethers.Wallet.createRandom()
      mnemonic = ethersWallet.mnemonic.phrase
    }

    let keystores: KeyStoreModel = new KeyStore()
    let keyExports: KeyStoreModel = new KeyStore()

    // ED25519
    let kp = this.getEd25519(mnemonic)
    keystores.ED25519 = kp.getSecret('hex')
    keyExports.ED25519 = await KeyConvert.getEd25519(kp)
    keyExports.ED25519.ldJsonPublic = await KeyConvert.createLinkedDataJsonFormat(
      LDCryptoTypes.Ed25519,
      kp as any,
      false,
    )

    // ES256K
    const kpec = this.getES256K(mnemonic) as ec.KeyPair
    keystores.ES256K = kpec.getPrivate('hex')
    keyExports.ES256K = await KeyConvert.getES256K(kpec)
    keyExports.ES256K.ldJsonPublic = await KeyConvert.createLinkedDataJsonFormat(
      LDCryptoTypes.JWK,
      // @ts-ignore
      { publicJwk: JSON.parse(keyExports.ES256K.ldSuite.publicKeyJwk) },
      false,
    )

    const keystoreMnemonicAsString = await ethersWallet.encrypt(
      options.passphrase,
    )

    const keystore: KeystoreDbModel = {
      _id: id,
      keypairs: keystores,
      keystoreSeed: keystoreMnemonicAsString,
      mnemonic: mnemonic,
      keypairExports: keyExports,
    }

    account.keystores.push(keystore)
    account.isActive = true
    account.isLocked = true
    account.currentKeystoreId = id

    await this.db.crypto(options.passphrase)
    await this.db.put(account)

    return this
  }

  protected async getPrivateKey(
    algorithm: AlgorithmTypeString,
    keystoreId: string,
  ): Promise<ec.KeyPair | eddsa.KeyPair> {
    const ks = (await this.getAccount()).keystores.find(
      (w) => w._id === keystoreId,
    )

    if (algorithm === 'ED25519') {
      const kp = new eddsa('ed25519')
      return kp.keyFromSecret(ks.keypairs.ED25519) as eddsa.KeyPair
    } else if (algorithm === 'P256') {
      const kp = new ec('p256')
      return kp.keyFromPrivate(ks.keypairs.P256) as ec.KeyPair
    } else if (algorithm === 'ES256K') {
      const kp = new ec('secp256k1')
      return kp.keyFromPrivate(ks.keypairs.ES256K) as ec.KeyPair
    }
  }

  protected async getPrivateKeyExports(
    algorithm: AlgorithmTypeString,
    keystoreId: string,
  ) {
    const ks = (await this.getAccount()).keystores.find(
      (w) => w._id === keystoreId,
    )
    return ks.keypairExports[algorithm]
  }

  public async canUse() {
    let ticket = null
    const init = this.accepted
    return new Promise((resolve) => {
      ticket = setInterval(() => {
        if (this.accepted !== init) {
          clearInterval(ticket)
          resolve(this.accepted)
          this.accepted = undefined
          return
        }
      }, 1000)
    })
  }

  /**
   * Signs with selected algorithm
   * @param algorithm Algorithm
   * @param payload Payload as buffer
   * @param options options
   */
  public async sign(
    algorithm: AlgorithmTypeString,
    keystoreId: string,
    payload: Buffer,
  ): Promise<[Error, any?]> {
    this.onRequestPassphraseSubscriber.next({
      type: 'request_tx',
      payload,
      algorithm,
    })

    const canUseIt = await this.canUse()

    let key
    if (canUseIt) {
      if (algorithm === 'ED25519') {
        key = await this.getPrivateKey(algorithm, keystoreId)
        return [null, key.sign(payload).toHex()]
      } else if (algorithm === 'ES256K') {
        key = await this.getPrivateKey(algorithm, keystoreId)
        return [null, key.sign(payload).toHex()]
      }
    }
    return [new Error('invalid_passphrase')]
  }

  /**
   * Signs a JWT for single recipient
   * @param algorithm Algorithm
   * @param payload Payload as buffer
   * @param options options
   */
  public async signJWT(
    algorithm: AlgorithmTypeString,
    keystoreId: string,
    payload: any,
    options: any,
  ): Promise<[Error, any?]> {
    this.onRequestPassphraseSubscriber.next({
      type: 'request_tx',
      payload,
      algorithm,
    })

    const canUseIt = await this.canUse()

    if (canUseIt) {
      const { pem } = await this.getPrivateKeyExports(algorithm, keystoreId)
      return [null, await JWTService.sign(pem, payload, options)]
    }
    return [new Error('invalid_passphrase')]
  }

  public async signJWTFromPublic(
    publicKey: any,
    payload: any,
    options: any,
  ): Promise<[Error, any?]> {
    this.onRequestPassphraseSubscriber.next({ type: 'request_tx', payload })

    const canUseIt = await this.canUse()

    if (canUseIt) {
      return [null, JWTService.sign(publicKey, payload, options)]
    }

    return [new Error('invalid_passphrase')]
  }

  /**
   * Encrypts JWE
   * @param algorithm Algorithm
   * @param payload Payload as buffer
   * @param overrideWithKey Uses this key instead of current wallet key
   *
   */
  public async encryptJWE(
    algorithm: AlgorithmTypeString,
    keystoreId: string,
    payload: any,
    overrideWithKey: any,
  ): Promise<[Error, any?]> {
    this.onRequestPassphraseSubscriber.next({
      type: 'request_tx',
      payload,
      algorithm,
    })

    const canUseIt = await this.canUse()

    if (canUseIt) {
      let jwk
      if (overrideWithKey === null) {
        const keys = await this.getPrivateKeyExports(algorithm, keystoreId)
        jwk = keys.jwk
      }
      // @ts-ignore
      return [null, await JOSEService.encrypt([jwk], payload)]
    }
    return [new Error('invalid_passphrase')]
  }

  public async decryptJWE(
    algorithm: AlgorithmTypeString,
    keystoreId: string,
    payload: any,
  ): Promise<[Error, any?]> {
    this.onRequestPassphraseSubscriber.next({
      type: 'request_tx',
      payload,
      algorithm,
    })

    const canUseIt = await this.canUse()

    if (canUseIt) {
      const { jwk } = await this.getPrivateKeyExports(algorithm, keystoreId)

      return [
        null,
        await JWE.createDecrypt(await JWK.asKey(jwk, 'jwk')).decrypt(payload),
      ]
    }
    return [new Error('invalid_passphrase')]
  }

  /**
   * Generates a mnemonic
   */
  public static generateMnemonic() {
    return ethers.Wallet.createRandom().mnemonic
  }

  public async unlockKeystore(id: string) {
    this.onRequestPassphraseSubscriber.next({ type: 'wallet', value: id })
    this.onRequestPassphraseWallet.subscribe(async (p) => {
      if (p.type !== 'ui') {
        this.accepted = p.accepted
      } else {
        try {
          this.db.crypto(p.passphrase)
          this.onRequestPassphraseSubscriber.next({ type: 'done', value: id })
        } catch (e) {
          this.onRequestPassphraseSubscriber.next({ type: 'error', error: e })
        }
      }
    })
  }

  /**
   * Derives a wallet from a path
   */
  public deriveFromPath(mnemonic: string, path: string): any {
    const node = ethers.utils.HDNode.fromMnemonic(mnemonic).derivePath(path)
    return node
  }

  /**
   * Gets EdDSA key pair
   */
  public getEd25519(mnemonic: string): eddsa.KeyPair {
    const ed25519 = new eddsa('ed25519')
    // const hdkey = HDKey.fromExtendedKey(HDNode.fromMnemonic(this.mnemonic).extendedKey);
    const { key } = getMasterKeyFromSeed(mnemonicToSeed(mnemonic))
    const keypair = ed25519.keyFromSecret(key)
    return keypair
  }

  public getES256K(mnemonic: string): ec.KeyPair {
    const ES256k = new ec('secp256k1')
    const keypair = ES256k.keyFromPrivate(
      ethers.utils.HDNode.fromMnemonic(mnemonic).privateKey,
    )
    return keypair
  }

  /**
   * Gets keystore from session db
   */
  async getAccount(): Promise<Account> {
    try {
      const item = await this.db.get('xdv:account')
      return item as Account
    } catch (e) {
      return null
    }
  }

  /**
   * Sets a keystore index, if keystore is diff, then clears lock (lock set to false)
   * @param id
   */
  async setAccountLock(lock: boolean) {
    let accountInstance: Account
    try {
      accountInstance = await this.db.get('xdv:account')
      accountInstance.isLocked = lock
      return this.db.put(accountInstance)
    } catch (e) {
      throw e
    }
  }
  async setCurrentKeystore(id: string) {
    let accountInstance: Account
    try {
      accountInstance = await this.db.get('xdv:account')
      accountInstance.currentKeystoreId = id
      return this.db.put(accountInstance)
    } catch (e) {
      throw e
    }
  }
}
