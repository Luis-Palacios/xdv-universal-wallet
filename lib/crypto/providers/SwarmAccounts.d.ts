import { SwarmWallet } from './SwarmWallet';
/**
 * Account management for swarm wallets
 */
export declare class SwarmAccounts {
    private client;
    constructor(options?: any);
    /**
     * Creates a wallet
     * @param username username
     * @param password password
     */
    createWallet(username: string, password: string): Promise<{
        xdv: SwarmWallet;
    }>;
    openFDS(username: string, password: string): Promise<any>;
}
