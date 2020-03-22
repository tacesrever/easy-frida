/// <reference types="frida-gum" />

export declare function findElfSegment(moduleOrName: Module | string, segName: string) : {addr: NativePointer, size: number} | null;

export declare function enumerateRanges() : ({base: NativePointer, end: NativePointer, size: number, prots: string, fileOffset: number, fileSize: number, name: string})[];

export declare function heapSearch(pattern: string) : MemoryScanMatch[];