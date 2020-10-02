/// <reference types="frida-gum" />
export declare function showJavaBacktrace(): void;
export declare function javaBacktrace(): string;
/**
 * show android log at console.
 */
export declare function showLogcat(level?: number): void;
interface libCallback {
    (inited: boolean): void;
}
/**
 * callback will be called when library loaded.
 * callback(false) when .init_array funcs not called,
 * callback(true) after.
 */
export declare function showlibevents(stop?: boolean): void;
export declare function libraryOnLoad(libname: string, callback: libCallback): void;
/**
 * when gadget already injected and use server, this should be called.
 */
export declare function avoidConflict(gadgetName?: string): void;
export declare function adbLog(...args: any[]): void;
/**
 * log click and activity resume event
 */
export declare function logScreen(): void;
/**
 * call setWebContentsDebuggingEnabled when WebView created.
 */
export declare function debugWebView(): void;
/**
 * show backtrace using libbacktrace in android.
 */
export declare function showBacktrace(tidOrContext?: number | CpuContext): void;
export declare enum DumpType {
    NativeBacktrace = 0,
    Tombstone = 1,
    JavaBacktrace = 2,
    AnyIntercept = 3
}
/**
 * dump backtrace using libdebuggerd_client.
 */
export declare function dumpBacktraceToFile(tid: number, type: DumpType, outfile: string): void;
export {};
