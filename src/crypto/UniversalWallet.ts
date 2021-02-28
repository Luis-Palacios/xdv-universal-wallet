import { VerifiableCredential } from 'did-jwt-vc'
import { KeystoreDbModel, Wallet } from './Wallet'
import {
  IIssueProps,
  IQueryProps,
  ISignerProps,
  ITransferProps,
  IUniversalWallet,
} from './IUniversalWallet'

export class UniversalWallet extends Wallet implements IUniversalWallet {
  /**
   * Imports a key
   * @param mnemonic Mnemonic
   * @param passphrase Passphrase
   */
  async import(mnemonic: string, passphrase: string): Promise<object> {
    this.addWallet({
      mnemonic,
      passphrase,
      accountName: '',
    })

    //TODO - Build JSON
    const a = await this.getAccount()
    const ks = a.keystores.find(
      (i) => i._id === a.currentKeystoreId,
    ) as KeystoreDbModel
    return ks
  }
  export(walletId: string, passphrase: string): Promise<object> {
    throw new Error('Method not implemented.')
  }
  async unlock(walletId: string, passphrase: string): Promise<object> {
    //TODO - Build JSON
    try {
      const a = await this.getAccount()
      const ks = a.keystores.find(
        (i) => i._id === a.currentKeystoreId,
      ) as KeystoreDbModel
      return ks
    } catch (e) {
      this.db.crypto(passphrase)
    }
  }
  async lock(passphrase: string): Promise<object> {
    //TODO - Build JSON
    try {
      const a = await this.getAccount()
      const ks = a.keystores.find(
        (i) => i._id === a.currentKeystoreId,
      ) as KeystoreDbModel
      this.db.crypto(passphrase)
    } catch (e) {
    }
    return {}
  }
  signRaw(buf: Uint8Array, options: ISignerProps): Promise<object> {
    throw new Error('Method not implemented.')
  }
  verifyRaw(buf: Uint8Array, options: ISignerProps): Promise<object> {
    throw new Error('Method not implemented.')
  }
  verify(vc: VerifiableCredential): Promise<object> {
    throw new Error('Method not implemented.')
  }
  issue(vc: VerifiableCredential, options: IIssueProps): Promise<object> {
    throw new Error('Method not implemented.')
  }
  prove(ids: string[], options: IIssueProps): Promise<object> {
    throw new Error('Method not implemented.')
  }
  transfer(options: ITransferProps): Promise<object> {
    throw new Error('Method not implemented.')
  }
  query(search: IQueryProps): Promise<object> {
    throw new Error('Method not implemented.')
  }
}
