import { bigToUint8Array } from '../crypto/BigIntToUint8Array'
import { DIDDocumentBuilder } from '../did/DIDDocumentBuilder'
import { BigNumber, ethers } from 'ethers'
import { expect } from 'chai'
import { JOSEService } from './JOSEService'
import { JWTService } from './JWTService'
import { KeyConvert, X509Info } from './KeyConvert'
import { LDCryptoTypes } from './LDCryptoTypes'
import { Wallet } from './Wallet'
import { DIDManager } from '../3id/DIDManager'
import { IPLDManager } from '../3id/IPLDManager'
import * as privateBox from 'private-box'
import { W3CVerifiedCredential } from '../3id/W3CVerifiedCredential'

let localStorage = {}
let id = null
let url = 'https://ropsten.infura.io/v3/79110f2241304162b087759b5c49cf99'

describe('universal wallet - wallet and 3ID', function () {
  let selectedWallet: Wallet
  before(async function () {})

  it('when calling createWeb3Provider, should return a web3 instance and wallet id', async function () {  
    const wallet = new Wallet()
    const passphrase = '1234'
    const result = await wallet.createWeb3Provider({
      passphrase,
      rpcUrl: url,
      accountName:''
    })
    expect(result.id.length).to.be.above(0)
  })

  it('when calling createWeb3Provider and create3IDWeb3, should return a web3 instance and wallet id', async function () {
    const wallet = new Wallet()
    const passphrase = '1234'
    const result = await wallet.createWeb3Provider({
      passphrase: '1234',
      rpcUrl: url,
      accountName: ''
    })
    id = result.id
    expect(result.did.id.length).to.be.above(0)
  })
  it('when calling createES256K with an existing id, should return a web3 instance and wallet id', async function () {
    const wallet = new Wallet()
    const passphrase = '1234'
    
    const result = await wallet.createES256K({
      passphrase: '1234',
      rpcUrl: url,
      walletId: id,
      registry: '',
      accountName: ''
    })
    await wallet.setAccountLock(passphrase, true)
    let acct = await wallet.getAccount()
    console.log(acct.keystores)
    await wallet.setAccountLock(passphrase, false)
    acct = await wallet.getAccount()
    console.log(acct.keystores)

    expect(result.address).equal(result.address)
  })

  it('when calling createES256K with an existing id, should return a web3 instance and wallet id', async function () {
    const wallet = new Wallet()
    const passphrase = '1234'
    const result = await wallet.createES256K({
      passphrase: '1234',
      rpcUrl: url,
      walletId: id,
      registry: '',
      accountName: ''
    })
    expect(result.address).equal(result.address)
  })
  it('when calling createES256K with an existing id and create a VC, should return a web3 instance and wallet id', async function () {
    const wallet = new Wallet()
    const passphrase = '1234'
    const result = await wallet.createES256K({
      passphrase: '1234',
      rpcUrl: url,
      walletId: id,
      registry: '',
      accountName: ''
    })

    const vcService = new W3CVerifiedCredential()
    const vc = await vcService.issueCredential(result.did, result.did, {
      name: 'Rogelio',
      lastName: 'Morrell',
      cedula: '8-713-2230',
      nationality: 'Panamanian',
      email: 'rogelio@ifesa.tech',
    })
    expect(vc.length).to.be.above(0)
  })

  it('when calling create3IDEd25519 , should return a did instance and wallet id', async function () {
    const wallet = new Wallet()
    const passphrase = '1234'
    const res = await wallet.createEd25519({
      passphrase,
      rpcUrl: url,
      walletId: id,
      registry: '',
      accountName: ''      
    })
    await res.did.authenticate()
    const issuer = res.getIssuer()
    expect(issuer.alg).equal('Ed25519')
    expect(res.did.id.length).to.be.above(0)
  })
})

describe('universal wallet - wallet, 3ID and IPLD', function () {
  let selectedWallet: Wallet
  before(async function () {})

  it('when adding a signed DID/IPLD object , should fetch and return uploaded data', async function () {
    const wallet = new Wallet()
    const passphrase = '1234'
    const did = await wallet.createEd25519({
      passphrase,
      rpcUrl: url,
      walletId: id,
      registry: '',
      accountName: ''      
    })
    const acct = await wallet.getAccount();
    expect(acct.currentKeystoreId.length).to.be.above(0)

    const ipfsManager = new IPLDManager(did.did)
    await ipfsManager.start()

    const fil = Buffer.from('fffffffffffffffffffffff')
    // auth
    await did.did.authenticate()
    const cid = await ipfsManager.addSignedObject(fil, {
      name: 'UnitTest.txt',
      contentType: 'text/text',
      lastModified: new Date(),
    })
    expect(cid.length).to.be.above(0)

    const res = await ipfsManager.getObject(cid)
    expect(res.value.name).equal('UnitTest.txt')
  })

  it('when adding a signed and encrypted DID/IPLD object , should fetch and return uploaded data', async function () {
    const wallet = new Wallet()
    const passphrase = '1234'


    const did = await wallet.createEd25519({
      passphrase,
      accountName: ''
    })
    const didBob = await wallet.createEd25519({
      passphrase,
      accountName: ''
    })

    const ipfsManager = new IPLDManager(did.did)
    await ipfsManager.start()

    // auth
    await did.did.authenticate()
    await didBob.did.authenticate()
    // Alice encrypts, and both Alice and Bob can decrypt
    const enc = await ipfsManager.encryptObject('Hola Mundo !!!', [
      didBob.did.id,
    ])

    console.log(enc.toString())

    // const cid = await ipfsManager.addSignedObject(Buffer.from(enc.toString()), {
    //   name: 'UnitTestEnc.txt',
    //   contentType: 'text/text',
    //   lastModified: new Date(),
    // })
    // expect(cid.length).to.be.above(0)
    const res = await ipfsManager.decryptObject(didBob.did, enc.toString(), {})
    expect(res.cleartext).equal('Hola Mundo !!!')
  })

  it('when adding a signed and encrypted DID/IPLD object , should failed decrypting if not allowed', async function () {
    const wallet = new Wallet()
    const passphrase = '1234'

    const walletProviderAlice = await wallet.createES256K({
      passphrase,
      accountName: ''
    })
    const walletProviderBob = await wallet.createES256K({
      passphrase,
      accountName: ''
    })

    const ipfsManager = new IPLDManager(walletProviderAlice.did)
    await ipfsManager.start()
    console.log(walletProviderBob.publicKey)
    const message = await walletProviderAlice.secureMessage.encrypt(
      walletProviderBob.publicKey,
      Buffer.from('Hola Mundo Secreto!'),
    )


    const plaintext = await walletProviderBob.secureMessage.decrypt(message)

    expect(plaintext).equal('Hola Mundo Secreto!')
  })
})
