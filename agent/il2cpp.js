
let cachedApi = null;
const ef = require("./easy_frida.js");
const na = require("./native.js");

const apiFunctions = {
    il2cpp_domain_get: ['pointer', []],
    il2cpp_domain_get_assemblies: ['pointer', ['pointer', 'pointer']],
    il2cpp_assembly_get_image: ['pointer', ['pointer']],
    il2cpp_image_get_name: ['pointer', ['pointer']],
    
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
    
    il2cpp_type_get_name: ['pointer', ['pointer']],
    il2cpp_type_get_object: ['pointer', ['pointer']],
    
    il2cpp_runtime_object_init: ['void', ['pointer']],
    il2cpp_runtime_invoke_convert_args: ['pointer', ['pointer', 'pointer', 'pointer', 'int', 'pointer']], 
    il2cpp_runtime_invoke: ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']], 
    
    il2cpp_thread_attach: ['pointer', ['pointer']], 
    il2cpp_thread_current: ['pointer', []], 
    il2cpp_thread_detach: ['void', ['pointer']], 
    il2cpp_thread_get_all_attached_threads: ['pointer', ['pointer']], 
    il2cpp_current_thread_get_stack_depth: ['int', []], 
    il2cpp_thread_get_stack_depth: ['int', ['pointer']], 
    il2cpp_current_thread_get_frame_at: ['bool', ['int', 'pointer']], 
    il2cpp_thread_get_frame_at: ['bool', ['pointer', 'int', 'pointer']],
}

function getApi() {
    if (cachedApi !== null) {
        return cachedApi;
    }
    
    const tempApi = {};
    const libil2cpp = Process.findModuleByName("libil2cpp.so");
    if(libil2cpp) {
        for(let name in apiFunctions) {
            const address = libil2cpp.findExportByName(name);
            const funcType = apiFunctions[name];
            if(address) tempApi[name] = new NativeFunction(address, funcType[0], funcType[1]);
            else {
                console.log(`[E] function ${name} not found`);
            }
        }
        cachedApi = tempApi;
        return cachedApi;
    }
    
    return null;
}

function getDomain() {
    const api = getApi();
    if(api === null) return;
    return api.il2cpp_domain_get();
}

let cachedImages = [];
function enumerateImages() {
    const api = getApi();
    if(api === null) return;
    let result = [];
    
    const domain = getDomain();
    const sizePtr = Memory.alloc(Process.pointerSize);
    
    const assemblies = api.il2cpp_domain_get_assemblies(domain, sizePtr);
    const size = sizePtr.readU32();
    if(cachedImages.length == size) return cachedImages;
    
    for(let i = 0; i < size; ++i) {
        const assembly = assemblies.add(i*Process.pointerSize).readPointer();
        const image = {};
        image.assembly = assembly;
        image.handle = api.il2cpp_assembly_get_image(assembly);
        image.name = api.il2cpp_image_get_name(image.handle).readCString();
        result.push(image);
    }
    cachedImages = result;
    return result;
}

function findImageByName(name) {
    const api = getApi();
    if(api === null) return;
    const images = enumerateImages();
    for(let i in images) {
        if(images[i].name === name) return image;
    }
    return null;
}

function isStaticField(field) {
    const api = getApi();
    if(api === null) return;
    const offset = api.il2cpp_field_get_offset(field);
    const attrs = api.il2cpp_field_get_flags(field);
    
    // FIELD_ATTRIBUTE_STATIC
    if(attrs & 0x10) return true;
    // THREAD_STATIC_FIELD_OFFSET
    if(offset === -1) return true;
    
    return false;
}

function isLocalField(field) {
    const api = getApi();
    if(api === null) return;
    if(isStaticField(field)) return false;
    const attrs = api.il2cpp_field_get_flags(field);
    if(attrs & 0x40) return false;
    return true;
}

function isStaticMethod(method) {
    const api = getApi();
    if(api === null) return;
    const attrs = api.il2cpp_method_get_flags(method, ptr(0));
    
    // Method_ATTRIBUTE_STATIC
    if(attrs & 0x10) return true;
    
    return false;
}

let cachedClass = {};
function fromClass(clz) {
    const api = getApi();
    if(api === null) return;
    
    const tmpPtr = Memory.alloc(Process.pointerSize);
    const self = {};
    let curclz = clz;
    let cachedMethods = {};
    self.$classHandle = clz;
    self.$className = api.il2cpp_class_get_name(clz).readCString();
    self.$namespace = api.il2cpp_class_get_namespace(clz).readCString();
    const methods = {};
    self.$methods = methods;
    while(!curclz.isNull()) {
        tmpPtr.writePointer(ptr(0));
        let field = api.il2cpp_class_get_fields(curclz, tmpPtr);
        while(!field.isNull()) {
            const name = api.il2cpp_field_get_name(field).readCString();
            if(isStaticField(field) && !self.hasOwnProperty(name)) {
                let curfield = field;
                Object.defineProperty(self, name, {
                    get: function () {
                        const fieldType = api.il2cpp_field_get_type(curfield);
                        const fieldClz = api.il2cpp_class_from_type(fieldType);
                        const valueSize = api.il2cpp_class_value_size(fieldClz, ptr(0));
                        const valuePtr = Memory.alloc(valueSize);
                        api.il2cpp_field_static_get_value(curfield, valuePtr);
                        if(!api.il2cpp_class_is_valuetype(fieldClz)) {
                            const valueHandle = valuePtr.readPointer();
                            return fromObject(valueHandle);
                        }
                        if(valueSize <= Process.pointerSize) return valuePtr.readPointer();
                        return valuePtr;
                    },
                    set: function (value) {
                        const fieldType = api.il2cpp_field_get_type(curfield);
                        const fieldClz = api.il2cpp_class_from_type(fieldType);
                        const valueSize = api.il2cpp_class_value_size(fieldClz, ptr(0));
                        if(valueSize <= Process.pointerSize) {
                            const valuePtr = Memory.alloc(Process.pointerSize);
                            valuePtr.writePointer(ptr(value));
                            api.il2cpp_field_static_set_value(curfield, valuePtr);
                        } else {
                            api.il2cpp_field_static_set_value(curfield, value);
                        }
                    }
                });
            }
            field = api.il2cpp_class_get_fields(curclz, tmpPtr);
        }
        
        tmpPtr.writePointer(ptr(0));
        let method = api.il2cpp_class_get_methods(curclz, tmpPtr);
        while(!method.isNull()) {
            const name = api.il2cpp_method_get_name(method).readCString();
            // if(isStaticMethod(method) && !methods.hasOwnProperty(name)) {
            if(!methods.hasOwnProperty(name)) {
                let curmethod = method;
                Object.defineProperty(methods, name, {
                    get: function () {
                        if(cachedMethods[name] === undefined) {
                            cachedMethods[name] = curmethod.readPointer();
                        }
                        
                        return cachedMethods[name];
                    },
                    set: function (newFunc) {
                        
                    }
                });
            }
            method = api.il2cpp_class_get_methods(curclz, tmpPtr);
        }
        curclz = api.il2cpp_class_get_parent(curclz);
    }
    return self;
}

function fromObject(handle) {
    const api = getApi();
    if(api === null) return;
    if(handle.isNull()) return null;
    const clz = api.il2cpp_object_get_class(handle);
    const self = fromClass(clz);
    let curclz = clz;
    let cachedMethods = {};
    const methods = self.$methods;
    self.$handle = handle;
    const tmpPtr = Memory.alloc(Process.pointerSize);
    while(!curclz.isNull()) {
        tmpPtr.writePointer(ptr(0));
        let field = api.il2cpp_class_get_fields(curclz, tmpPtr);
        while(!field.isNull()) {
            const name = api.il2cpp_field_get_name(field).readCString();
            if(isLocalField(field) && !self.hasOwnProperty(name)) {
                let curfield = field;
                Object.defineProperty(self, name, {
                    get: function () {
                        const fieldType = api.il2cpp_field_get_type(curfield);
                        const fieldClz = api.il2cpp_class_from_type(fieldType);
                        if( api.il2cpp_class_is_valuetype(fieldClz)
                         && api.il2cpp_class_value_size(fieldClz, ptr(0)) <= Process.pointerSize) {
                            const valuePtr = Memory.alloc(Process.pointerSize);
                            api.il2cpp_field_get_value(self.$handle, curfield, valuePtr);
                            return valuePtr.readPointer();
                        } else {
                            const valueHandle = api.il2cpp_field_get_value_object(curfield, self.$handle);
                            return fromObject(valueHandle);
                        }
                    },
                    set: function (value) {
                        const fieldType = api.il2cpp_field_get_type(curfield);
                        const fieldClz = api.il2cpp_class_from_type(fieldType);
                        if( api.il2cpp_class_is_valuetype(fieldClz) 
                         && api.il2cpp_class_value_size(fieldClz, ptr(0)) <= Process.pointerSize) {
                            const valuePtr = Memory.alloc(Process.pointerSize);
                            valuePtr.writePointer(ptr(value));
                            api.il2cpp_field_set_value(self.$handle, curfield, valuePtr);
                        } else {
                            api.il2cpp_field_set_value_object(self.$handle, curfield, ptr(value));
                        }
                    }
                });
            }
            field = api.il2cpp_class_get_fields(curclz, tmpPtr);
        }
        
        // tmpPtr.writePointer(ptr(0));
        // let method = api.il2cpp_class_get_methods(curclz, tmpPtr);
        // while(!method.isNull()) {
            // const name = api.il2cpp_method_get_name(method).readCString();
            // if(!isStaticMethod(method) && !methods.hasOwnProperty(name)) {
                // let curmethod = method;
                // Object.defineProperty(methods, name, {
                    // get: function () {
                        // if(cachedMethods[name] === undefined) {
                            // cachedMethods[name] = curmethod.readPointer();
                        // }
                        
                        // return cachedMethods[name];
                    // },
                    // set: function (newFunc) {
                        
                    // }
                // });
            // }
            // method = api.il2cpp_class_get_methods(curclz, tmpPtr);
        // }
        curclz = api.il2cpp_class_get_parent(curclz);
    }
    return self;
}

function fromName(image, namespace, name) {
    const api = getApi();
    if(api === null) return null;
    if(typeof(namespace) === 'string') namespace = Memory.allocUtf8String(namespace);
    if(typeof(name) === 'string') name = Memory.allocUtf8String(name);
    
    if(typeof(image) === 'number') image = ptr(image);
    else if(typeof(image) === 'string') {
        let tmpimageobj = findImageByName(image);
        if(tmpimageobj) {
            image = tmpimageobj.handle;
        }
        else {
            console.log('can not find image', image);
            return null;
        }
    }
    else if(image["handle"] !== undefined) image = image.handle;
    
    const clz = api.il2cpp_class_from_name(image, namespace, name);
    if(clz.isNull()) return null;
    const result = fromClass(clz);
    return result;
}

function fromFullname(fullname) {
    let splited = fullname.split(".");
    let name = splited[splited.length - 1];
    let namespace = splited.slice(0, splited.length - 1).join(".");
    let result = null;
    enumerateImages().forEach(function(image) {
        if(result === null) {
            result = fromName(image, namespace, name);
        }
    });
    return result;
}

function findObjectByName(fullname) {
    const api = getApi();
    if(api === null) return;
    
    const clz = fromFullname(fullname);
    if(clz === null) return null;
    const type = api.il2cpp_class_get_type(clz);
    const obj = api.il2cpp_type_get_object(type);
    if(obj === null) return null;
    return fromObject(obj);
}

function perform(fn) {
    const api = getApi();
    if(api === null) {
        let attached = false;
        na.libraryOnLoad("libil2cpp.so", function(inited) {
            if(inited && !attached) {
                attached = true;
                const il2cpp_init = Module.getExportByName("libil2cpp.so", "il2cpp_init");
                Interceptor.attach(il2cpp_init, {
                    onLeave: function(retVal) {
                        fn();
                        Interceptor.revert(il2cpp_init);
                        Interceptor.flush();
                    }
                });
                Interceptor.flush();
            }
            
        });
    }
    else {
        fn();
    }
}
// function getAllThreads() {
    // const api = getApi();
    // if(api === null) return;
    // const tmpPtr = Memory.alloc(Process.pointerSize);
    // const threads = api.il2cpp_thread_get_all_attached_threads(tmpPtr);
    // const size = tmpPtr.readU32();
    // for(let i = 0; i < size; ++i) {
        // let thread = threads.add(i*Process.pointerSize);
        // console.log(thread.readPointer());
    // }
// }

module.exports = {
    getApi,
    getDomain,
    enumerateImages,
    findImageByName,
    fromObject,
    fromName,
    fromFullname,
    findObjectByName,
    perform
}