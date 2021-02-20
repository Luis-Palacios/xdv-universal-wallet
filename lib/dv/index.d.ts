export declare const CedulaInputTypes: {
    N: number[];
    NT: number[];
    E: number[];
    P: number[];
    I: number[];
    AV: number[];
};
export declare class DV {
    private account;
    private nodeUrl;
    private isMainnet?;
    private contract;
    constructor(account: string, nodeUrl: string, isMainnet?: boolean);
    initialize(): Promise<void>;
    calculate(cedulaType: number[], segment1: number[], segment2: number[], segment3: number[], segment4: number[]): Promise<any>;
}
