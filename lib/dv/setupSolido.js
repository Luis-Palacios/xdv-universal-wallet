"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.setupSolido = void 0;
const solido_1 = require("@decent-bet/solido");
const solido_provider_ethers_1 = require("solido-provider-ethers");
const DVAbi = require('./DV.abi');
const DVContractImport = DVAbi.DV;
const setupSolido = async (ethersProvider, defaultAccount, network = 'ropsten') => {
    // const networks: any = {
    //   3: 'ropsten',
    //   1: 'mainnet',
    //   4: 'rinkeby',
    // }
    // Create Solido Module
    const contractMappings = [
        {
            name: "DV",
            import: DVContractImport,
            provider: solido_provider_ethers_1.EthersPlugin,
            enableDynamicStubs: true
        },
    ];
    // Create Solido Module
    const solido = new solido_1.SolidoModule(contractMappings);
    const provider = ethersProvider;
    // Configure reactive solido store
    const store = {
        state: {},
        mutations: {},
        mapEvents: {},
        mapActions: {}
    };
    const contracts = solido
        .bindContracts({
        ethers: {
            provider,
            options: {
                defaultAccount,
                provider,
                network,
                store
            }
        }
    })
        .connect();
    return contracts;
};
exports.setupSolido = setupSolido;
//# sourceMappingURL=setupSolido.js.map