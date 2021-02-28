"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UniversalWallet = void 0;
const Wallet_1 = require("./Wallet");
class UniversalWallet extends Wallet_1.Wallet {
    /**
     * Imports a key
     * @param mnemonic Mnemonic
     * @param passphrase Passphrase
     */
    async import(mnemonic, passphrase) {
        this.addWallet({
            mnemonic,
            passphrase,
            accountName: '',
        });
        //TODO - Build JSON
        const a = await this.getAccount();
        const ks = a.keystores.find((i) => i._id === a.currentKeystoreId);
        return ks;
    }
    export(walletId, passphrase) {
        throw new Error('Method not implemented.');
    }
    async unlock(walletId, passphrase) {
        //TODO - Build JSON
        try {
            const a = await this.getAccount();
            const ks = a.keystores.find((i) => i._id === a.currentKeystoreId);
            return ks;
        }
        catch (e) {
            this.db.crypto(passphrase);
        }
    }
    async lock(passphrase) {
        //TODO - Build JSON
        try {
            const a = await this.getAccount();
            const ks = a.keystores.find((i) => i._id === a.currentKeystoreId);
            this.db.crypto(passphrase);
        }
        catch (e) {
        }
        return {};
    }
    signRaw(buf, options) {
        throw new Error('Method not implemented.');
    }
    verifyRaw(buf, options) {
        throw new Error('Method not implemented.');
    }
    verify(vc) {
        throw new Error('Method not implemented.');
    }
    issue(vc, options) {
        throw new Error('Method not implemented.');
    }
    prove(ids, options) {
        throw new Error('Method not implemented.');
    }
    transfer(options) {
        throw new Error('Method not implemented.');
    }
    query(search) {
        throw new Error('Method not implemented.');
    }
}
exports.UniversalWallet = UniversalWallet;
//# sourceMappingURL=UniversalWallet.js.map