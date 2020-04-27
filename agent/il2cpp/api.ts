
const apiFunctions: {
    [index: string]: [string, string[]]
} = {
    il2cpp_free: ['pointer', ['pointer']],
    il2cpp_domain_get: ['pointer', []],
    il2cpp_domain_get_assemblies: ['pointer', ['pointer', 'pointer']],
    il2cpp_assembly_get_image: ['pointer', ['pointer']],
    il2cpp_image_get_name: ['pointer', ['pointer']],
    il2cpp_string_new: ['pointer', ['pointer']],
    
    il2cpp_object_get_class: ['pointer', ['pointer']],
    il2cpp_class_from_name: ['pointer', ['pointer', 'pointer', 'pointer']],
    il2cpp_class_from_type: ['pointer', ['pointer']],
    il2cpp_class_get_type: ['pointer', ['pointer']],
    il2cpp_class_get_name: ['pointer', ['pointer']],
    il2cpp_class_get_namespace: ['pointer', ['pointer']],
    il2cpp_class_get_parent: ['pointer', ['pointer']],
    il2cpp_class_get_fields: ['pointer', ['pointer', 'pointer']], 
    il2cpp_class_get_methods: ['pointer', ['pointer', 'pointer']], 
    il2cpp_class_is_valuetype: ['bool', ['pointer']], 
    il2cpp_class_value_size: ['int', ['pointer', 'pointer']], 
    il2cpp_class_get_method_from_name: ['pointer', ['pointer', 'pointer', 'int']],
    
    il2cpp_field_get_name: ['pointer', ['pointer']],
    il2cpp_field_get_offset: ['int', ['pointer']],
    il2cpp_field_get_type: ['pointer', ['pointer']],
    il2cpp_field_get_flags: ['int', ['pointer']],
    il2cpp_field_get_value: ['void', ['pointer', 'pointer', 'pointer']],
    il2cpp_field_get_value_object: ['pointer', ['pointer', 'pointer']],
    il2cpp_field_static_get_value: ['void', ['pointer', 'pointer']],
    il2cpp_field_set_value: ['void', ['pointer', 'pointer', 'pointer']],
    il2cpp_field_set_value_object: ['void', ['pointer', 'pointer', 'pointer']],
    il2cpp_field_static_set_value: ['void', ['pointer', 'pointer']],
    
    il2cpp_method_get_name: ['pointer', ['pointer']],
    il2cpp_method_get_param_count: ['int', ['pointer']],
    il2cpp_method_get_flags: ['int', ['pointer', 'pointer']],
    il2cpp_method_get_class: ['pointer', ['pointer']],
    il2cpp_method_get_return_type: ['pointer', ['pointer']],
    il2cpp_method_get_param: ['pointer', ['pointer', 'int']],
    il2cpp_method_get_param_name: ['pointer', ['pointer', 'int']],
    
    il2cpp_type_get_name: ['pointer', ['pointer']],
    il2cpp_type_get_object: ['pointer', ['pointer']],
    
    il2cpp_runtime_object_init: ['void', ['pointer']],
    il2cpp_runtime_invoke_convert_args: ['pointer', ['pointer', 'pointer', 'pointer', 'int', 'pointer']], 
    il2cpp_runtime_invoke: ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']],
    il2cpp_thread_attach: ['pointer', ['pointer']],
    il2cpp_thread_detach: ['void', ['pointer']],
    il2cpp_thread_current: ['pointer', []],
    il2cpp_format_exception: ['void', ['pointer', 'pointer', 'int']], 
    il2cpp_format_stack_trace: ['void', ['pointer', 'pointer', 'int']], 
    il2cpp_get_exception_argument_null: ['pointer', ['pointer']],
    il2cpp_object_new: ['pointer', ['pointer']],
}

interface Il2cppApi {
    module: Module,
    il2cpp_free: (pointer: NativePointer) => NativePointer,
    il2cpp_domain_get: () => NativePointer,
    il2cpp_domain_get_assemblies: (domain: NativePointer, sizePtr: NativePointer) => NativePointer,
    il2cpp_assembly_get_image: (assembly: NativePointer) => NativePointer,
    il2cpp_image_get_name: (image: NativePointer) => NativePointer,
    il2cpp_string_new: (string: NativePointer) => NativePointer,
    
    il2cpp_object_get_class: (object: NativePointer) => NativePointer,
    il2cpp_class_from_name: (image: NativePointer, namespace: NativePointer, name: NativePointer) => NativePointer,
    il2cpp_class_from_type: (type: NativePointer) => NativePointer,
    il2cpp_class_get_type: (clz: NativePointer) => NativePointer,
    il2cpp_class_get_name: (clz: NativePointer) => NativePointer,
    il2cpp_class_get_namespace: (clz: NativePointer) => NativePointer,
    il2cpp_class_get_parent: (clz: NativePointer) => NativePointer,
    il2cpp_class_get_fields: (clz: NativePointer, iterPtr: NativePointer) => NativePointer, 
    il2cpp_class_get_methods: (clz: NativePointer, iterPtr: NativePointer) => NativePointer, 
    il2cpp_class_is_valuetype: (clz: NativePointer) => boolean, 
    il2cpp_class_value_size: (clz: NativePointer, align: NativePointer) => number, 
    il2cpp_class_get_method_from_name: (clz: NativePointer, name: NativePointer, argcount: number) => NativePointer,
    
    il2cpp_field_get_name: (field: NativePointer) => NativePointer,
    il2cpp_field_get_offset: (field: NativePointer) => number,
    il2cpp_field_get_type: (field: NativePointer) => NativePointer,
    il2cpp_field_get_flags: (field: NativePointer) => number,
    il2cpp_field_get_value: (object: NativePointer, field: NativePointer, out: NativePointer) => void,
    il2cpp_field_get_value_object: (field: NativePointer, object: NativePointer) => NativePointer,
    il2cpp_field_static_get_value: (field: NativePointer, out: NativePointer) => void,
    il2cpp_field_set_value: (object: NativePointer, field: NativePointer, valuePtr: NativePointer) => void,
    il2cpp_field_set_value_object: (object: NativePointer, field: NativePointer, value: NativePointer) => void,
    il2cpp_field_static_set_value: (field: NativePointer, value: NativePointer) => void,
    
    il2cpp_method_get_name: (method: NativePointer) => NativePointer,
    il2cpp_method_get_param_count: (method: NativePointer) => number,
    il2cpp_method_get_flags: (method: NativePointer, out: NativePointer) => number,
    il2cpp_method_get_class: (method: NativePointer) => NativePointer,
    il2cpp_method_get_return_type: (method: NativePointer) => NativePointer,
    il2cpp_method_get_param: (method: NativePointer, paramIdx: number) => NativePointer,
    il2cpp_method_get_param_name: (method: NativePointer, paramIdx: number) => NativePointer,
    
    il2cpp_type_get_name: (type: NativePointer) => NativePointer,
    il2cpp_type_get_object: (type: NativePointer) => NativePointer,
    
    il2cpp_runtime_object_init: (object: NativePointer) => void,
    il2cpp_runtime_invoke_convert_args: (method: NativePointer, object: NativePointer, params: NativePointer, paramCount: number, except: NativePointer) => NativePointer, 
    il2cpp_runtime_invoke: (method: NativePointer, object: NativePointer, params: NativePointer, except: NativePointer) => NativePointer,
    il2cpp_thread_attach: (domain: NativePointer) => NativePointer,
    il2cpp_thread_detach: (thread: NativePointer) => void,
    il2cpp_thread_current: () => NativePointer,
    il2cpp_format_exception: (except: NativePointer, message: NativePointer, size: number) => void, 
    il2cpp_format_stack_trace: (except: NativePointer, output: NativePointer, size: number) => void, 
    il2cpp_get_exception_argument_null: (clz: NativePointer) => NativePointer,
    il2cpp_object_new: (clz: NativePointer) => NativePointer,
}

let cachedApi: Il2cppApi;
/**
 * get libil2cpp native api functions
 */
export function getApi() {
    if (cachedApi !== undefined) return cachedApi;
    const tempApi: Il2cppApi = Object.create(null);
    let libil2cpp = Process.getModuleByName("libil2cpp.so");
    tempApi.module = libil2cpp;
    for(let fname of Object.keys(apiFunctions) as Array<keyof Il2cppApi>) {
        const address = libil2cpp.findExportByName(fname);
        const funcType = apiFunctions[fname];
        if(address) tempApi[fname] = new NativeFunction(address, funcType[0], funcType[1]) as any;
        else {
            console.log(`[E] function ${fname} not found`);
        }
    }
    cachedApi = tempApi;
    return cachedApi;
};