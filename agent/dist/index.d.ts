declare global {
    interface String {
        toMatchPattern(): string;
    }
}
export declare let interact: string;
export declare function rpcCall(funcName: string, args: any, noreturn?: boolean): Promise<any>;
export declare let isServer: boolean;
