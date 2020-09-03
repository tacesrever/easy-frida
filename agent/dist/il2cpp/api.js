"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const apiFunctions = {
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
};
let cachedApi;
/**
 * get libil2cpp native api functions
 */
function getApi() {
    if (cachedApi !== undefined)
        return cachedApi;
    const tempApi = Object.create(null);
    let libil2cpp = Process.getModuleByName("libil2cpp.so");
    tempApi.module = libil2cpp;
    for (let fname of Object.keys(apiFunctions)) {
        const address = libil2cpp.findExportByName(fname);
        const funcType = apiFunctions[fname];
        if (address)
            tempApi[fname] = new NativeFunction(address, funcType[0], funcType[1]);
        else {
            console.log(`[E] Can't found export function ${fname} in libil2cpp.so`);
        }
    }
    cachedApi = tempApi;
    return cachedApi;
}
exports.getApi = getApi;
;
//# sourceMappingURL=api.js.map