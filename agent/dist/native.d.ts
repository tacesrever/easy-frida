export declare function showBacktrace(context?: CpuContext): void;
/**
 * similar to hexdump,
 * for lazy people who don't want to write "console.log(hexdump(...))" when debuging.
 */
export declare function d(address: number | NativePointer, size?: number): void;
/**
 * warpper for NativeFunction, add 'string' type.
 * slower, just for convenience.
 */
type NativeFunctionReturnTypeMapEx = NativeFunctionReturnTypeMap & {
    string: string;
};
type NativeFunctionReturnTypeEx = RecursiveKeysOf<NativeFunctionReturnTypeMapEx>;
type NativeFunctionReturnValueEx = RecursiveValuesOf<NativeFunctionReturnTypeMapEx>;
type GetNativeFunctionReturnValueEx<T extends NativeFunctionReturnTypeEx> = GetValue<NativeFunctionReturnTypeMapEx, NativeFunctionReturnValueEx, NativeFunctionReturnTypeEx, T>;
type NativeFunctionArgumentTypeMapEx = NativeFunctionArgumentTypeMap & {
    string: string;
};
type NativeFunctionArgumentTypeEx = RecursiveKeysOf<NativeFunctionArgumentTypeMapEx>;
type NativeFunctionArgumentValueEx = RecursiveValuesOf<NativeFunctionArgumentTypeMapEx>;
type GetNativeFunctionArgumentValueEx<T extends NativeFunctionArgumentTypeEx> = GetValue<NativeFunctionArgumentTypeMapEx, NativeFunctionArgumentValueEx, NativeFunctionArgumentTypeEx, T>;
export interface NativeFunctionEx<RetType extends NativeFunctionReturnValueEx, ArgTypes extends NativeFunctionArgumentValueEx[] | []> extends NativePointer {
    (...args: ArgTypes): RetType;
    apply(thisArg: NativePointerValue | null | undefined, args: ArgTypes): RetType;
    call(thisArg?: NativePointerValue | null, ...args: ArgTypes): RetType;
}
export declare function importfunc<RetType extends NativeFunctionReturnTypeEx, ArgTypes extends NativeFunctionArgumentTypeEx[] | []>(libnameOrFuncaddr: string | NativePointerValue | null, funcName: string, retType: RetType, argTypes: ArgTypes, abiOrOptions?: NativeABI | NativeFunctionOptions): NativeFunctionEx<GetNativeFunctionReturnValueEx<RetType>, ResolveVariadic<Extract<GetNativeFunctionArgumentValueEx<ArgTypes>, unknown[]>>>;
/**
 * set custom debug symbol name to range.
 * show as name or name+offset.
 */
export declare function setName(address: number | NativePointer, size: number, name: string): void;
export declare function symbolName(address: number | NativePointer): string;
/**
 * show addrinfo from DebugSymbol.fromAddress, findModuleByAddress and findRangeByAddress.
 */
export declare function showAddrInfo(address: number | NativePointer): void;
/**
 * dump memory to file.
 */
export declare function dumpMem(address: number | NativePointer, size: number, outname: string): void;
export declare function traceCalled(libnameOrFuncaddr: string | NativePointerValue | null, funcName: string): InvocationListener;
/**
 * typeformat: T.name, where T is:
 * p: Pointer
 * i: int
 * s: String
 * d%d|%x: data and it's length
 * v: Pointer => Value
 * w: Pointer => Pointer => Value
 * example: traceFunction(null, 'open', 'i.fd', ['s.name', 'p.flag'])
 */
export declare function traceFunction(libnameOrFuncaddr: string | NativePointerValue | null, funcName: string, retType: string | string[], argTypes: string[], hooks?: ScriptInvocationListenerCallbacks): InvocationListener;
/**
 * https://codeshare.frida.re/@oleavr/read-std-string/
 */
export declare function readStdString(strHandle: NativePointer): string;
export declare function cprintf(format: string, args: NativePointer[], vaArgIndex?: number, maxSize?: number): string;
export declare function showThreads(): void;
export declare function showThread(tid: number): void;
export declare function showCpuContext(context: CpuContext): void;
export declare function showDiasm(pc: NativePointer): void;
export declare function traceExecBlockByStalkerAt(addr: NativePointer, onExecBlock: (ctx: CpuContext, block: any[]) => void): void;
export declare function showNativeExecption(handler?: ExceptionHandlerCallback): void;
export declare function setThreadStackRangeNames(): void;
export {};
