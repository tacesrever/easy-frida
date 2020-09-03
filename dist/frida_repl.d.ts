/// <reference types="node" />
import repl = require('repl');
export declare class FridaRepl {
    private localEval;
    private remoteEval;
    private onResult;
    useLocalEval: boolean;
    repl: repl.REPLServer;
    constructor(localEval: (code: string) => any, remoteEval: (code: string) => Promise<any>, onResult: (result: any) => void);
    start(): repl.REPLServer;
    private replEval;
    private remoteCompleter;
    private evalCallback;
}
