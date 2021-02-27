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

export interface KeystoreDbModel {
  _id: any
  keypairs: KeyStoreModel
  keystoreSeed: any
  mnemonic: string
  keypairExports: KeyStoreModel
  publicKeys?: any
}

export interface ICreateOrLoadWalletProps {
  walletId?: string
  passphrase: string
  registry?: string
  rpcUrl?: string
  mnemonic?: string
}

export interface KeyStoreModel {
  ES256K: any
  P256: any
  ED25519: any
}

export class KeyStore implements KeyStoreModel {
  public ED25519: any
  public ES256K: any
  public P256: any
  constructor() {}
}

export interface Account {
  _id: string
  id: string
  timestamp: Date
  isActive: boolean
  isLocked: boolean
}

export class Wallet {
  public id: string
  public onRequestPassphraseSubscriber: Subject<any> = new Subject<any>()
  public onRequestPassphraseWallet: Subject<any> = new Subject<any>()
  public onSignExternal: Subject<any> = new Subject<{
    isEnabled: boolean
    signature: string | Buffer
  }>()
  private db = new PouchDB('xdv:web:wallet')
  ethersWallet: any
  mnemonic: any
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
      wallet = await wallet.createWallet(options.passphrase, options)
      ks = await wallet.db.get(wallet.id)
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
      id: wallet.id,
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
      wallet = await wallet.createWallet(options.passphrase)
      ks = await wallet.db.get(wallet.id)
    }
    const kp = new eddsa('ed25519')
    const kpInstance = kp.keyFromSecret(ks.keypairs.ED25519) as eddsa.KeyPair
    const didManager = new DIDManager()
    const { did, getIssuer } = await didManager.create3ID_Ed25519(kpInstance)

    return ({
      did,
      getIssuer,
      id: wallet.id,
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
      wallet = await wallet.createWallet(options.passphrase)
      web3 = new Web3(options.rpcUrl)
      ks = await wallet.db.get(wallet.id)
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
      id: wallet.id,
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
  public async createWallet(password: string, options: any = {}) {
    let id = Buffer.from(ethers.utils.randomBytes(100)).toString('base64')
    if (options.id) {
      id = options.id
    }
    let mnemonic = options.mnemonic

    if (mnemonic) {
      this.ethersWallet = ethers.Wallet.fromMnemonic(mnemonic)
    } else {
      this.ethersWallet = ethers.Wallet.createRandom()
      mnemonic = this.ethersWallet.mnemonic.phrase
    }

    this.mnemonic = mnemonic

    let keystores: KeyStoreModel = new KeyStore()
    let keyExports: KeyStoreModel = new KeyStore()

    // ED25519
    let kp = this.getEd25519()
    keystores.ED25519 = kp.getSecret('hex')
    keyExports.ED25519 = await KeyConvert.getEd25519(kp)
    keyExports.ED25519.ldJsonPublic = await KeyConvert.createLinkedDataJsonFormat(
      LDCryptoTypes.Ed25519,
      kp as any,
      false,
    )

    // ES256K
    const kpec = this.getES256K() as ec.KeyPair
    keystores.ES256K = kpec.getPrivate('hex')
    keyExports.ES256K = await KeyConvert.getES256K(kpec)
    keyExports.ES256K.ldJsonPublic = await KeyConvert.createLinkedDataJsonFormat(
      LDCryptoTypes.JWK,
      // @ts-ignore
      { publicJwk: JSON.parse(keyExports.ES256K.ldSuite.publicKeyJwk) },
      false,
    )

    const keystoreMnemonicAsString = await this.ethersWallet.encrypt(password)

    const model: KeystoreDbModel = {
      _id: id,
      keypairs: keystores,
      keystoreSeed: keystoreMnemonicAsString,
      mnemonic: mnemonic,
      keypairExports: keyExports,
    }

    await this.db.crypto(password)
    await this.db.put(model)

    this.id = id

    return this
  }

  public async getPrivateKey(
    algorithm: AlgorithmTypeString,
  ): Promise<ec.KeyPair | eddsa.KeyPair> {
    const ks: KeystoreDbModel = await this.db.get(this.id)

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

  public async getPrivateKeyExports(algorithm: AlgorithmTypeString) {
    const ks: KeystoreDbModel = await this.db.get(this.id)
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
        key = await this.getPrivateKey(algorithm)
        return [null, key.sign(payload).toHex()]
      } else if (algorithm === 'ES256K') {
        key = await this.getPrivateKey(algorithm)
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
      const { pem } = await this.getPrivateKeyExports(algorithm)
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
        const keys = await this.getPrivateKeyExports(algorithm)
        jwk = keys.jwk
      }
      // @ts-ignore
      return [null, await JOSEService.encrypt([jwk], payload)]
    }
    return [new Error('invalid_passphrase')]
  }

  public async decryptJWE(
    algorithm: AlgorithmTypeString,
    payload: any,
  ): Promise<[Error, any?]> {
    this.onRequestPassphraseSubscriber.next({
      type: 'request_tx',
      payload,
      algorithm,
    })

    const canUseIt = await this.canUse()

    if (canUseIt) {
      const { jwk } = await this.getPrivateKeyExports(algorithm)

      return [
        null,
        await JWE.createDecrypt(await JWK.asKey(jwk, 'jwk')).decrypt(payload),
      ]
    }
    return [new Error('invalid_passphrase')]
  }
  /**
   * Encrypts JWE with multiple keys
   * @param algorithm
   * @param payload
   */
  public async encryptMultipleJWE(
    keys: any[],
    algorithm: AlgorithmTypeString,
    payload: any,
  ): Promise<[Error, any?]> {
    this.onRequestPassphraseSubscriber.next({
      type: 'request_tx',
      payload,
      algorithm,
    })

    const canUseIt = await this.canUse()

    if (canUseIt) {
      const { jwk } = await this.getPrivateKeyExports(algorithm)
      // @ts-ignore
      return [null, await JOSEService.encrypt([jwk, ...keys], payload)]
    }
    return [new Error('invalid_passphrase')]
  }
  /**
   * Generates a mnemonic
   */
  public static generateMnemonic() {
    return ethers.Wallet.createRandom().mnemonic
  }

  public setActiveWalletId(id: string) {}

  public async open(id: string) {
    this.id = id
    this.onRequestPassphraseSubscriber.next({ type: 'wallet' })
    this.onRequestPassphraseWallet.subscribe(async (p) => {
      if (p.type !== 'ui') {
        this.accepted = p.accepted
      } else {
        try {
          this.db.crypto(p.passphrase)
          const ks = await this.db.get(id)
          this.mnemonic = ks.mnemonic
          this.onRequestPassphraseSubscriber.next({ type: 'done' })
        } catch (e) {
          this.onRequestPassphraseSubscriber.next({ type: 'error', error: e })
        }
      }
    })
  }

  /**
   * Derives a new child Wallet
   */
  public deriveChild(sequence: number, derivation = `m/44'/60'/0'/0`): any {
    const masterKey = ethers.utils.HDNode.fromMnemonic(this.mnemonic)
    return masterKey.derivePath(`${derivation}/${sequence}`)
  }

  public get path() {
    return this.ethersWallet.path
  }

  public get address() {
    return this.ethersWallet.getAddress()
  }
  /**
   * Derives a wallet from a path
   */
  public deriveFromPath(path: string): any {
    const node = ethers.utils.HDNode.fromMnemonic(this.mnemonic).derivePath(
      path,
    )
    return node
  }

  /**
   * Gets EdDSA key pair
   */
  public getEd25519(): eddsa.KeyPair {
    const ed25519 = new eddsa('ed25519')
    // const hdkey = HDKey.fromExtendedKey(HDNode.fromMnemonic(this.mnemonic).extendedKey);
    const { key } = getMasterKeyFromSeed(mnemonicToSeed(this.mnemonic))
    const keypair = ed25519.keyFromSecret(key)
    return keypair
  }

  public getES256K(): ec.KeyPair {
    const ES256k = new ec('secp256k1')
    const keypair = ES256k.keyFromPrivate(
      ethers.utils.HDNode.fromMnemonic(this.mnemonic).privateKey,
    )
    return keypair
  }

  keygen(alg: AlgorithmType) {
    if (alg === AlgorithmType.ED25519) {
      return this.getEd25519()
    } else {
      return this.getES256K()
    }
  }

  /**
   * Sets a keystore index, if keystore is diff, then clears lock (lock set to false)
   * @param id
   */
  async setCurrent(account: string, lock: boolean) {
    const templ = {
      _id: 'xdv:account:current',
      id: account,

      isActive: true,
      isLocked: true,
      timestamp: new Date(),
    } as Account
    try {
      let ref: Account = await this.db.get('xdv:account:current')
      if (account !== ref.id) {
        // if diff, then clear lock=false
        ref = await this.db.put({
          _id: 'xdv:account:current',
          id: account,
          _rev: ref._rev,
        })
      }
      // @ts-ignore
      templ._rev = ref._rev
      if (lock !== undefined) {
        templ.isLocked = lock
      }
      return this.db.put(templ)
    } catch (e) {
      return this.db.put(templ)
    }
  }
}
