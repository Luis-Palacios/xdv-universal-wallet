import { VerifiableCredential } from "did-jwt-vc";
import { Wallet } from "./Wallet";
import { IIssueProps, IQueryProps, ISignerProps, ITransferProps, IUniversalWallet } from "./IUniversalWallet";


export  class UniversalWallet
extends Wallet
implements  IUniversalWallet {

    /**
     * Imports a key
     * @param mnemonic Mnemonic
     * @param passphrase Passphrase
     */
    async import(mnemonic: string, passphrase: string): Promise<object> {
        const w  = await Wallet.createES256K({
            mnemonic,
            passphrase,
        });

        //TODO - Build JSON 
        return w 
    }
    export(walletId: string, passphrase: string): Promise<object> {
        throw new Error("Method not implemented.");
    }
    unlock(walletId: string, passphrase: string): Promise<object> {
        throw new Error("Method not implemented.");
    }
    lock(walletId: string): Promise<object> {
        throw new Error("Method not implemented.");
    }
    signRaw(buf: Uint8Array, options: ISignerProps): Promise<object> {
        throw new Error("Method not implemented.");
    }
    verifyRaw(buf: Uint8Array, options: ISignerProps): Promise<object> {
        throw new Error("Method not implemented.");
    }
    verify(vc: VerifiableCredential): Promise<object> {
        throw new Error("Method not implemented.");
    }
    issue(vc: VerifiableCredential, options: IIssueProps): Promise<object> {
        throw new Error("Method not implemented.");
    }
    prove(ids: string[], options: IIssueProps): Promise<object> {
        throw new Error("Method not implemented.");
    }
    transfer(options: ITransferProps): Promise<object> {
        throw new Error("Method not implemented.");
    }
    query(search: IQueryProps): Promise<object> {
        throw new Error("Method not implemented.");
    }
    
}