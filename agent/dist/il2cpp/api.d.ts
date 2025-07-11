interface Il2cppApi {
    module: Module;
    il2cpp_free: (pointer: NativePointer) => NativePointer;
    il2cpp_domain_get: () => NativePointer;
    il2cpp_domain_get_assemblies: (domain: NativePointer, sizePtr: NativePointer) => NativePointer;
    il2cpp_assembly_get_image: (assembly: NativePointer) => NativePointer;
    il2cpp_image_get_name: (image: NativePointer) => NativePointer;
    il2cpp_string_new: (string: NativePointer) => NativePointer;
    il2cpp_object_get_class: (object: NativePointer) => NativePointer;
    il2cpp_class_from_name: (image: NativePointer, namespace: NativePointer, name: NativePointer) => NativePointer;
    il2cpp_class_from_type: (type: NativePointer) => NativePointer;
    il2cpp_class_get_type: (clz: NativePointer) => NativePointer;
    il2cpp_class_get_name: (clz: NativePointer) => NativePointer;
    il2cpp_class_get_namespace: (clz: NativePointer) => NativePointer;
    il2cpp_class_get_parent: (clz: NativePointer) => NativePointer;
    il2cpp_class_get_fields: (clz: NativePointer, iterPtr: NativePointer) => NativePointer;
    il2cpp_class_get_methods: (clz: NativePointer, iterPtr: NativePointer) => NativePointer;
    il2cpp_class_is_valuetype: (clz: NativePointer) => boolean;
    il2cpp_class_value_size: (clz: NativePointer, align: NativePointer) => number;
    il2cpp_class_get_method_from_name: (clz: NativePointer, name: NativePointer, argcount: number) => NativePointer;
    il2cpp_field_get_name: (field: NativePointer) => NativePointer;
    il2cpp_field_get_offset: (field: NativePointer) => number;
    il2cpp_field_get_type: (field: NativePointer) => NativePointer;
    il2cpp_field_get_flags: (field: NativePointer) => number;
    il2cpp_field_get_value: (object: NativePointer, field: NativePointer, out: NativePointer) => void;
    il2cpp_field_get_value_object: (field: NativePointer, object: NativePointer) => NativePointer;
    il2cpp_field_static_get_value: (field: NativePointer, out: NativePointer) => void;
    il2cpp_field_set_value: (object: NativePointer, field: NativePointer, valuePtr: NativePointer) => void;
    il2cpp_field_set_value_object: (object: NativePointer, field: NativePointer, value: NativePointer) => void;
    il2cpp_field_static_set_value: (field: NativePointer, value: NativePointer) => void;
    il2cpp_method_get_name: (method: NativePointer) => NativePointer;
    il2cpp_method_get_param_count: (method: NativePointer) => number;
    il2cpp_method_get_flags: (method: NativePointer, out: NativePointer) => number;
    il2cpp_method_get_class: (method: NativePointer) => NativePointer;
    il2cpp_method_get_return_type: (method: NativePointer) => NativePointer;
    il2cpp_method_get_param: (method: NativePointer, paramIdx: number) => NativePointer;
    il2cpp_method_get_param_name: (method: NativePointer, paramIdx: number) => NativePointer;
    il2cpp_type_get_name: (type: NativePointer) => NativePointer;
    il2cpp_type_get_object: (type: NativePointer) => NativePointer;
    il2cpp_runtime_object_init: (object: NativePointer) => void;
    il2cpp_runtime_invoke_convert_args: (method: NativePointer, object: NativePointer, params: NativePointer, paramCount: number, except: NativePointer) => NativePointer;
    il2cpp_runtime_invoke: (method: NativePointer, object: NativePointer, params: NativePointer, except: NativePointer) => NativePointer;
    il2cpp_thread_attach: (domain: NativePointer) => NativePointer;
    il2cpp_thread_detach: (thread: NativePointer) => void;
    il2cpp_thread_current: () => NativePointer;
    il2cpp_format_exception: (except: NativePointer, message: NativePointer, size: number) => void;
    il2cpp_format_stack_trace: (except: NativePointer, output: NativePointer, size: number) => void;
    il2cpp_get_exception_argument_null: (clz: NativePointer) => NativePointer;
    il2cpp_object_new: (clz: NativePointer) => NativePointer;
}
/**
 * get libil2cpp native api functions
 */
export declare function getApi(): Il2cppApi;
export {};
