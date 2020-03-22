/// <reference types="frida-gum" />

export declare function backtrace(context?: CpuContext) : void;
/**
 * similar to hexdump,
 * for lazy people who don't want to write "console.log(hexdump({...}))" when debuging.
 */
export declare function d(address: number | NativePointer, size?: number) : void;
/**
 * warpper for NativeFunction, add 'string' type.
 * slower, just for convenience.
 */
export declare function makefunction(libnameOrFuncaddr: string | NativePointerValue | null, funcName: string, retType: NativeType, argTypes: NativeType[], abiOrOptions?: NativeABI | NativeFunctionOptions) : CallableFunction | null;
/**
 * set custom debug symbol name to range.
 * show as name or name+offset.
 */
export declare function setName(address: number | NativePointer, size: number, name: string) : void;
export declare function symbolName(address: number | NativePointer) : string;
/**
 * return is like 'rw-'
 */
export declare function getProtection(address: number | NativePointer) : string | null;
/**
 * show addrinfo from DebugSymbol.fromAddress, findModuleByAddress and findRangeByAddress.
 */
export declare function showAddrInfo(address: number | NativePointer) : void;
/**
 * dump memory to file.
 */
export declare function dumpMem(address: number | NativePointer, size:number, outname: string): void;
export declare function traceCalled(libnameOrFuncaddr: string | NativePointerValue | null, funcName: string) : InvocationListener;
/**
 * typeformat: T.name, where T is: \
 * p: Pointer \
 * i: int \
 * s: String \
 * d%d: data and it's length\
 * v: Pointer => Value \
 * w: Pointer => Pointer => Value \
 * example: traceFunction(null, 'open', 'i.fd', ['s.name', 'p.flag'])
 */
export declare function traceFunction(libnameOrFuncaddr: string | NativePointerValue | null, funcName: string, retType: string, argTypes: string[], hooks?: ScriptInvocationListenerCallbacks) : InvocationListener;
/**
 * proxy for module operations.
 */
export let modules : any;
/**
 * https://codeshare.frida.re/@oleavr/read-std-string/
 */
export declare function readStdString(strHandle: NativePointer) : string;

export declare function cprintf(format: string, args: NativePointer[], vaArgIndex: number): string;

export declare function showThreads() : void;

