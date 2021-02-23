import { bigToUint8Array } from '../crypto/BigIntToUint8Array'
import { DIDDocumentBuilder } from '../did/DIDDocumentBuilder'
import { BigNumber, ethers } from 'ethers'
import { expect } from 'chai'
import { JOSEService } from '../crypto/JOSEService'
import { JWTService } from '../crypto/JWTService'
import { KeyConvert, X509Info } from '../crypto/KeyConvert'
import { LDCryptoTypes } from '../crypto/LDCryptoTypes'
import { Wallet } from '../crypto/Wallet'
import { DIDManager } from './DIDManager'
import { DriveManager } from './DriveManager'
import { IPFSManager } from './IPFSManager'
import * as privateBox from 'private-box'
import { W3CVerifiedCredential } from './W3CVerifiedCredential'
import moment from 'moment'

let localStorage = {}

describe('DID specs', function () {
  let selectedWallet: Wallet
  let id = null
  let url = 'https://ropsten.infura.io/v3/79110f2241304162b087759b5c49cf99'
  before(async function () {})

  it('when KYC onboarding should pay with blockchain and register to get verified', async function () {
    //Register Name, Email and Ether account
    const personalinfo = {
      name: 'John Doe',
      email: 'jd@gmail.com',
      account: '0x',
    }

    //Pay Services and return TX Hash

    const txhash = function payKYCService() {
      return '0xa'
    }
    //API redirects to request Wallet signature
    const result = await Wallet.createWeb3Provider({
      passphrase: '1234',
      rpcUrl: url,
    })
    const sig = await result.did.createJWS({
      name: 'Personal Signing',
      txhash,
      timestamp: moment().unix(),
    })

    const sigEth = ethers.utils.splitSignature(sig.signatures[0].signature)

    // Create DID
    const resultCreated = await function registerDID() {
      // ecrecover
      return '0xb'
    }

    // Optional - create DID backup in Swarm
    expect(result.id.length).to.be.above(0)
  })

  it('when change owner, should validate it is', async function () {
    //Register Name, Email and Ether account
    const personalinfo = {
      name: 'John Doe',
      email: 'jd@gmail.com',
      account: '0x',
    }

    //Pay Services and return TX Hash

    const txhash = function payKYCService() {
      return '0xa'
    }
    //API redirects to request Wallet signature
    const result = await Wallet.createWeb3Provider({
      passphrase: '1234',
      rpcUrl: url,
    })
    const sig = await result.did.createJWS({
      name: 'Personal Signing',
      txhash,
      timestamp: moment().unix(),
    })

    const sigEth = ethers.utils.splitSignature(sig.signatures[0].signature)

    // Create DID
    const resultCreated = await function registerDID() {
      // ecrecover
      return '0xb'
    }
    // Optional - create DID backup in Swarm

    // Change owner
    await result.did.changeOwner('0xc')

    // Add Delegate
    const since = moment().unix() + (60*60*1)
    await result.did.addDelegate('0xd', {
      delegateType: '',
      expiresIn: since,
    });

    expect(result.id.length).to.be.above(0)
  })
})
///
