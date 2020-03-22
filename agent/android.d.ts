/// <reference types="frida-gum" />

export declare function javaBacktrace(): void;
/**
 * backtrace use android libbacktrace.
 */
export declare function backtrace(tidOrContext?: number | CpuContext): void;
/**
 * show android log at console.
 */
export declare function showLogcat(level: number): void;
/**
 * callback will be called when library loaded. \
 * callback(0) when init funcs not called, \
 * callback(1) after.
 */
export declare function libraryOnLoad(libname: string, callback: (inited: number) => void): void;

export declare function avoidConflict(): void;
/**
 * log click and activity changes
 */
export declare function logScreen(): void;
/**
 * for chrome's inspect
 */
export declare function debugWebView(): void;