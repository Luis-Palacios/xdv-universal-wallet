import { EdDSASigner, ES256KSigner } from 'did-jwt';
import { ThreeIdConnect,  EthereumAuthProvider } from '3id-connect';
import { Ed25519Provider } from 'key-did-provider-ed25519'
import KeyResolver from '@ceramicnetwork/key-did-resolver'
import { DID, DIDOptions } from 'dids'
import { BNInput, ec, eddsa } from 'elliptic';

export class DIDManager {


    /**
     * Create 3ID
     * using XDV
     * @param privateKeyBytes EdDSA secret
     * @param privateKeyHex EdDSA secret hex
     */
    async create3ID_Ed25519(edDSAKeyPair: eddsa.KeyPair) {
        let seed = edDSAKeyPair.getSecret().slice(0, 32);

        const provider = new Ed25519Provider(seed)
        const did = new DID({ provider, resolver: KeyResolver.getResolver() } as unknown as DIDOptions)
        const issuer = () => ({
            signer: (data: eddsa.Bytes) => {
                return edDSAKeyPair.sign(data).toHex();
            },
            alg: 'Ed25519',
            did: did.id,
        });
    
        return { did, getIssuer: issuer };
    }    


    /**
     * Create 3ID
     * using XDV
     * @param privateKey Private key
     * @param web3provider Web3 Provider
     * @param address address
     */
    async create3IDWeb3(ecKeyPair: ec.KeyPair, web3provider: any, address: any) {
        const threeid = new ThreeIdConnect();
        const authProvider = new EthereumAuthProvider(web3provider, address);
        await threeid.connect(authProvider) 
        const did = new DID({ provider: (await threeid.getDidProvider()) as any, resolver: KeyResolver.getResolver() } as unknown)
        const issuer = () => ({
            signer: (data: BNInput) => {
                return ecKeyPair.sign(data);
            },
            alg: 'ES256K',
            did: did.id,
        });

        return { did, getIssuer: issuer };

    }    
}