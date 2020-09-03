/// <reference types="frida-gum" />
export declare function readFile(filePath: string): {
    base: NativePointer;
    size: number;
};
export declare function ELFHeader(base: NativePointer): any;
export declare function findElfSegment(moduleOrName: string | Module, segName: string): {
    addr: NativePointer;
    size: number;
};
export declare function enumerateRanges(): any[];
export declare function heapSearch(pattern: string): MemoryScanMatch[];
export declare function dumplib(name: string, outfile: string): void;
