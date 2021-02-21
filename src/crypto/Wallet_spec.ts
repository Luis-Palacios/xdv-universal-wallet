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
import { DriveManager } from '../3id/DriveManager'
import { IPFSManager } from '../3id/IPFSManager'
import * as privateBox from 'private-box'
import { W3CVerifiedCredential } from '../3id/W3CVerifiedCredential'

let localStorage = {}

describe('universal wallet - wallet and 3ID', function () {
  let selectedWallet: Wallet
  let id = null
  let url = 'https://ropsten.infura.io/v3/79110f2241304162b087759b5c49cf99'
  before(async function () {})

  it('when calling createWeb3Provider, should return a web3 instance and wallet id', async function () {
    const result = await Wallet.createWeb3Provider({
      passphrase: '1234',
      rpcUrl: url,
    })
    expect(result.id.length).to.be.above(0)
  })

  it('when calling createWeb3Provider and create3IDWeb3, should return a web3 instance and wallet id', async function () {
    const result = await Wallet.createWeb3Provider({
      passphrase: '1234',
      rpcUrl: url,
    })
    id = result.id
    expect(result.did.id.length).to.be.above(0)
  })

  it('when calling createES256K with an existing id, should return a web3 instance and wallet id', async function () {
    const result = await Wallet.createES256K({
      passphrase: '1234',
      rpcUrl: url,
      walletid: id,
      registry: '',
    })
    expect(result.did.address).equal(result.address)
  })
  it('when calling createES256K with an existing id and create a VC, should return a web3 instance and wallet id', async function () {
    const result = await Wallet.createES256K({
      passphrase: '1234',
      rpcUrl: url,
      walletid: id,
      registry: '',
    })

    const vcService = new W3CVerifiedCredential()
    const vc = await vcService.issueCredential(result.did, result.did, {
      name: 'Rogelio',
      lastName: 'Morrell',
      cedula: '8-713-2230',
      nationality: 'Panamanian',
      email: 'rogelio@ifesa.tech'
    })
    expect(vc.length).to.be.above(0)
  })

  it('when calling create3IDEd25519 , should return a did instance and wallet id', async function () {
    const res = await Wallet.create3IDEd25519({
      passphrase: 'abcdef123456',
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
    const did = await Wallet.create3IDEd25519({
      passphrase: 'abcdef123456',
    })
    expect(did.id.length).to.be.above(0)

    const ipfsManager = new IPFSManager(did.did)
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
    const did = await Wallet.create3IDEd25519({
      passphrase: 'abcdef123456',
    })
    const didBob = await Wallet.create3IDEd25519({
      passphrase: 'abcdef123456!@#$%^^&*',
    })
    expect(did.id.length).to.be.above(0)

    const ipfsManager = new IPFSManager(did.did)
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

  xit('when adding a signed and encrypted DID/IPLD object , should failed decrypting if not allowed', async function () {
    const walletProviderAlice = await Wallet.create3IDEd25519({
      passphrase: 'abcdef123456',
    })
    const walletProviderBob = await Wallet.create3IDEd25519({
      passphrase: 'abcdef123456!@#$%^^&*',
    })

    await walletProviderAlice.did.authenticate()
    await walletProviderBob.did.authenticate()

    const ipfsManager = new IPFSManager(walletProviderAlice.did)
    await ipfsManager.start()

    // Alice encrypts, and only Alice can decrypt
    const x25519BobPub = bigToUint8Array(walletProviderBob.x25519)

    const enc = privateBox.encrypt(Buffer.from('Hola Mundo !!! 2021'), [
      walletProviderBob.encKey,
    ])

    console.log(
      Buffer.from(enc).toString('base64'),
      walletProviderBob.encKey,
      x25519BobPub,
    )

    const text = privateBox.decrypt(Buffer.from(enc), x25519BobPub)

    console.log(text)
    // const cid = await ipfsManager.addSignedObject(Buffer.from(enc.toString()), {
    //   name: 'UnitTestEnc.txt',
    //   contentType: 'text/text',
    //   lastModified: new Date(),
    // })
    // expect(cid.length).to.be.above(0)
    //    try {
    // const res = await ipfsManager.decryptObject(
    //   did.did,
    //   enc.toString(),
    //   {},
    // )

    // } catch (e) {
    // }
  })
})
