import { Wallet } from '../Wallet';
export declare class SwarmWallet extends Wallet {
    fds: any;
    fdsUser: any;
    constructor(fds: any);
    setUser(user: any): void;
    getUser(): any;
}
