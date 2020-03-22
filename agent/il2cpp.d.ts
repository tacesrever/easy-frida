/// <reference types="frida-gum" />

interface Il2cppApi {
    il2cpp_free: NativeFunction,
    il2cpp_domain_get: NativeFunction,
    il2cpp_domain_get_assemblies: NativeFunction,
    il2cpp_assembly_get_image: NativeFunction,
    il2cpp_image_get_name: NativeFunction,
    il2cpp_string_new: NativeFunction,
    
    il2cpp_object_get_class: NativeFunction,
    il2cpp_class_from_name: NativeFunction,
    il2cpp_class_from_type: NativeFunction,
    il2cpp_class_get_type: NativeFunction,
    il2cpp_class_get_name: NativeFunction,
    il2cpp_class_get_namespace: NativeFunction,
    il2cpp_class_get_parent: NativeFunction,
    il2cpp_class_get_fields: NativeFunction, 
    il2cpp_class_get_methods: NativeFunction, 
    il2cpp_class_is_valuetype: NativeFunction, 
    il2cpp_class_value_size: NativeFunction, 
    il2cpp_class_get_method_from_name: NativeFunction,
    
    il2cpp_field_get_name: NativeFunction,
    il2cpp_field_get_offset: NativeFunction,
    il2cpp_field_get_type: NativeFunction,
    il2cpp_field_get_flags: NativeFunction,
    il2cpp_field_get_value: NativeFunction,
    il2cpp_field_get_value_object: NativeFunction,
    il2cpp_field_static_get_value: NativeFunction,
    il2cpp_field_set_value: NativeFunction,
    il2cpp_field_set_value_object: NativeFunction,
    il2cpp_field_static_set_value: NativeFunction,
    
    il2cpp_method_get_name: NativeFunction,
    il2cpp_method_get_param_count: NativeFunction,
    il2cpp_method_get_flags: NativeFunction,
    il2cpp_method_get_class: NativeFunction,
    il2cpp_method_get_return_type: NativeFunction,
    il2cpp_method_get_param: NativeFunction,
    il2cpp_method_get_param_name: NativeFunction,
    
    il2cpp_type_get_name: NativeFunction,
    il2cpp_type_get_object: NativeFunction,
    
    il2cpp_runtime_object_init: NativeFunction,
    il2cpp_runtime_invoke_convert_args: NativeFunction, 
    il2cpp_runtime_invoke: NativeFunction, 
    il2cpp_format_exception: NativeFunction, 
    il2cpp_format_stack_trace: NativeFunction, 
    il2cpp_get_exception_argument_null: NativeFunction,
    il2cpp_object_new: NativeFunction
}

interface Image {
    assembly: NativePointer,
    handle: NativePointer,
    name: string
}

/**
 * dump il2cpp symbols use https://github.com/tacesrever/Il2CppParser \
 * require libparser compiled and pushed at /data/local/tmp/libparser.so
 */
export declare function dump(addrfile: string, outbasename: string): void;
/**
 * get libil2cpp native api functions (not all)
 */
export declare function getApi(): Il2cppApi;
export declare function getDomain(): NativePointer;
export declare function enumerateImages(): Image[];
export declare function findImageByName(name: string): Image;
/**
 * get il2cpp object warpper by it's address. \
 * then you can get obj.prop, or set obj.prop = ? \
 * or do anything from it's class.
 */
export declare function fromObject(handle: number | NativePointer): any;
export declare function fromName(image: Image | NativePointer | number, namespace: string, name: string): any;
/**
 * get il2cpp class by it's name. \
 * then you can get class.func.ptr for attach or replace, \
 * get func info by print class.func.info \
 * call class.staticfunc(...args), class.objfunc(obj, ...args) \
 * get class.staticValueName, or set class.staticValueName = ?
 */
export declare function fromFullname(name: string): any;
/**
 * call callback after libil2cpp loaded, android only.
 */
export declare function perform(callback: () => void): void;
/**
 * read a .net string, if maxlen seted and str is too long, show ... after maxlen.
 */
export declare function readString(handle: number | NativePointer | {$handle: NativePointer}, maxlen?: number): string;
/**
 * construct a .net string, return il2cpp object's pointer
 */
export declare function newString(s: string): NativePointer | null;