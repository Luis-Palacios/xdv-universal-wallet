"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SwarmAccounts = void 0;
const ethers_1 = require("ethers");
const SwarmWallet_1 = require("./SwarmWallet");
const fds = require('fds.js');
/**
 * Account management for swarm wallets
 */
class SwarmAccounts {
    constructor(options = {}) {
        this.client = new fds(Object.assign({}, {
            swarmGateway: 'https://swarm.fairdatasociety.org',
        }, options));
    }
    /**
     * Creates a wallet
     * @param username username
     * @param password password
     */
    async createWallet(username, password) {
        const mnemonic = SwarmWallet_1.SwarmWallet.generateMnemonic();
        const swarmWallet = new SwarmWallet_1.SwarmWallet(this.client);
        const ethersWallet = ethers_1.ethers.Wallet.fromMnemonic(mnemonic.phrase);
        const privateKey = ethersWallet.privateKey;
        const publicKey = ethersWallet.publicKey;
        const options = { id: publicKey, mnemonic: mnemonic.phrase };
        const user = await this.client.RestoreAccountFromPrivateKey(username, password, privateKey);
        const wallet = await swarmWallet.createWallet(password, options);
        wallet.setUser(user);
        return { xdv: wallet };
    }
    async openFDS(username, password) {
        const user = await this.client.UnlockAccount(username, password);
        return user;
    }
}
exports.SwarmAccounts = SwarmAccounts;
//# sourceMappingURL=SwarmAccounts.js.map