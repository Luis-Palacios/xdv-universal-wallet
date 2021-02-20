"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SwarmWallet = void 0;
const Wallet_1 = require("../Wallet");
class SwarmWallet extends Wallet_1.Wallet {
    constructor(fds) {
        super();
        this.fds = fds;
    }
    setUser(user) {
        this.fdsUser = user;
    }
    getUser() {
        return this.fdsUser;
    }
}
exports.SwarmWallet = SwarmWallet;
//# sourceMappingURL=SwarmWallet.js.map