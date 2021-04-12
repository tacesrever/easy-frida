/// <reference types="frida-gum" />
interface Image {
    name: string | null;
    handle: NativePointer;
    assembly: NativePointer;
}
interface Il2cppClass {
    [index: string]: any;
    $classHandle: NativePointer;
    $className: string | null;
    $namespace: string | null;
}
interface Il2cppObject extends Il2cppClass {
    $handle: NativePointer;
    $arraySize?: number;
    $arrayPtr?: NativePointer;
    $str?: string;
}
/**
 * dump il2cpp symbols use https://github.com/tacesrever/Il2CppParser
 * require libparser compiled and pushed at /data/local/tmp/libparser.so
 */
export declare function dump(addrfile: string, outname: string): void;
/**
 * enumerate loaded Images.
 */
export declare function enumerateImages(): Image[];
export declare function findImageByName(name: string): Image;
/**
 * get il2cpp object warpper by object pointer.
 */
export declare function fromObject(handle: NativePointer | number): Il2cppObject | null;
/**
 * get il2cpp class warpper by it's image, namespace and name.
 */
export declare function fromName(image: Image | string | NativePointer | number, namespace: string | NativePointer, name: string | NativePointer): Il2cppClass;
/**
 * get il2cpp class warpper by it's fullname.
 */
export declare function fromFullname(fullname: string): Il2cppClass;
/**
 * ensure current thread is attach to il2cpp main domain.
 */
export declare function perform(callback: () => void): void;
/**
 * read a .net string, if maxlen seted and str is too long, show ... after maxlen.
 */
export declare function readString(handle: number | NativePointer | {
    $handle: NativePointer;
}, maxlen?: number): string;
/**
 * construct a .net string, return il2cpp object's pointer
 */
export declare function newString(s: string): NativePointer;
export declare function enumerateAssemblies(): {
    assembly: Il2cppObject;
    name: string;
}[];
export declare function enumerateTypes(filter: string[]): {
    [index: string]: string[];
};
export {};
