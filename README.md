# xdv-universal-wallet
XDV Universal Wallet

Creates a 3ID protocol enabled Ed25519 or Web3 provider

## Example

```typescript
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

```

## API

### crypto/Wallet


#### static async createES256K(options: any)
  
Creates an universal wallet for ES256K

Parameters
* @param options { passphrase, walletid, rpcUrl }


#### static async create3IDEd25519(options: any)
  
Creates an universal wallet for Ed25519

Parameters
* @param options { passphrase, walletid, rpcUrl }


#### static async createWeb3Provider(options: any)
  
Creates an universal wallet for Web3Provider

Parameters
* @param options { passphrase, walletid, rpcUrl }

### 3id/DIDManager

### 3id/DriveManager

### 3id/IPFSManager

### 3id/W3CVerifiedCredential


#### issueCredential(did: DID, issuer: any, holderInfo: any)
  
Issues a Verified Credential

Parameters
* @param options { passphrase, walletid, rpcUrl }
