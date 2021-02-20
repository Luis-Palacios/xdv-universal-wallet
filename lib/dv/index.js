"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DV = exports.CedulaInputTypes = void 0;
const ethers_1 = require("ethers");
const setupSolido_1 = require("./setupSolido");
const BN = require('bn.js');
let ruc20 = [
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
];
exports.CedulaInputTypes = {
    N: [5],
    NT: [4, 3],
    E: [5],
    P: [7],
    I: [9],
    AV: [1, 5],
};
class DV {
    constructor(account, nodeUrl, isMainnet) {
        this.account = account;
        this.nodeUrl = nodeUrl;
        this.isMainnet = isMainnet;
    }
    async initialize() {
        const network = this.isMainnet ? 'mainnet' : 'ropsten';
        const contracts = await setupSolido_1.setupSolido(new ethers_1.ethers.providers.JsonRpcProvider(this.nodeUrl), this.account, network);
        this.contract = contracts.DV;
    }
    async calculate(cedulaType, segment1, segment2, segment3, segment4) {
        const id = [
            ...cedulaType,
            ...segment1,
            ...segment2,
            ...segment3,
            ...segment4,
        ];
        let ruc21 = [...ruc20.slice(0, 20 - id.length), ...id, 0];
        const resp = await this.contract.methods.calc(ruc21);
        const dvRepuesta = resp.map(i => i.toString()).join('');
        return dvRepuesta;
    }
}
exports.DV = DV;
//# sourceMappingURL=index.js.map