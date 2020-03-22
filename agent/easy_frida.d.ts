/// <reference types="frida-gum" />
/// <reference types="node" />

declare global {
    interface String {
        toMatchPattern(): string;
    }
    let enableInteract: boolean;
}

export declare let isServer: boolean;
export declare let interact: string;
export declare function rpcCall(funcName: string, args: any, noreturn?: boolean): Promise<any>;