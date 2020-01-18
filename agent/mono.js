
let cachedApi = null;
const ef = require("./easy_frida.js");
const na = require("./native.js");
const makefunction = na.makefunction;

const apiFunctions = {
    mono_free: ['pointer', ['pointer']],
    mono_domain_get: ['pointer', []],
    mono_domain_get_assemblies: ['pointer', ['pointer', 'int']],
    mono_get_root_domain: ['pointer', []],
    mono_assembly_foreach: ['void', ['pointer', 'pointer']],
    mono_assembly_get_image: ['pointer', ['pointer']],
    mono_image_get_name: ['pointer', ['pointer']],
    mono_string_new: ['pointer', ['pointer', 'int']],
    
    mono_object_get_class: ['pointer', ['pointer']],
    mono_class_from_name: ['pointer', ['pointer', 'pointer', 'pointer']],
    mono_class_get_type: ['pointer', ['pointer']],
    mono_class_get_name: ['pointer', ['pointer']],
    mono_class_get_namespace: ['pointer', ['pointer']],
    mono_class_get_parent: ['pointer', ['pointer']],
    mono_class_get_fields: ['pointer', ['pointer', 'pointer']], 
    mono_class_try_get_vtable: ['pointer', ['pointer', 'pointer']], 
    mono_class_get_methods: ['pointer', ['pointer', 'pointer']], 
    mono_class_is_valuetype: ['bool', ['pointer']], 
    mono_class_value_size: ['int', ['pointer', 'pointer']], 
    mono_class_get_method_from_name: ['pointer', ['pointer', 'pointer', 'int']],
    
    mono_field_get_name: ['pointer', ['pointer']],
    mono_field_get_offset: ['int', ['pointer']],
    mono_field_get_type: ['pointer', ['pointer']],
    mono_field_get_flags: ['int', ['pointer']],
    mono_field_get_value: ['void', ['pointer', 'pointer', 'pointer']],
    mono_field_get_value_object: ['pointer', ['pointer', 'pointer', 'pointer']],
    mono_field_static_get_value: ['void', ['pointer', 'pointer', 'pointer']],
    mono_field_set_value: ['void', ['pointer', 'pointer', 'pointer']],
    mono_field_static_set_value: ['void', ['pointer', 'pointer', 'pointer']],
    
    mono_method_get_name: ['pointer', ['pointer']],
    mono_method_get_name_full: ['pointer', ['pointer', 'int', 'int', 'int']],
    mono_method_get_flags: ['int', ['pointer', 'pointer']],
    mono_method_get_class: ['pointer', ['pointer']],
    
    mono_compile_method: ['pointer', ['pointer']],
    mono_jit_compile_method: ['pointer', ['pointer', 'pointer']],
    mono_jit_compile_method_jit_only: ['pointer', ['pointer', 'pointer']],
    mono_jit_find_compiled_method: ['pointer', ['pointer', 'pointer']],
    
    mono_type_get_name: ['pointer', ['pointer']],
    mono_type_get_object: ['pointer', ['pointer']],
    mono_class_from_mono_type: ['pointer', ['pointer']],
    
    mono_runtime_object_init: ['void', ['pointer']],
    mono_runtime_invoke: ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']], 
    mono_get_exception_argument_null: ['pointer', ['pointer']],
    mono_object_new: ['pointer', ['pointer']],
}

function getApi() {
    if (cachedApi !== null) {
        return cachedApi;
    }
    const tempApi = {};
    let libmono = Process.findModuleByName("libmono.so");
    if(libmono === null) libmono = Process.findModuleByName("libmonobdwgc-2.0.so");
    if(libmono) {
        for(let name in apiFunctions) {
            const address = libmono.findExportByName(name);
            const funcType = apiFunctions[name];
            if(address) tempApi[name] = new NativeFunction(address, funcType[0], funcType[1]);
            else {
                if(ef.isServer)
                    console.log(`[E] function ${name} not found`);
            }
        }
        tempApi.domain = tempApi.mono_get_root_domain();
        cachedApi = tempApi;
        return cachedApi;
    }
    
    return null;
}

let cachedImages = [];
function enumerateImages() {
    const api = getApi();
    if(api === null) return null;
    let result = [];
    
    const gPtrArray = api.mono_domain_get_assemblies(api.domain, 0);
    const assemblies = gPtrArray.readPointer();
    const size = gPtrArray.add(4).readU32();
    if(cachedImages.length == size) return cachedImages;
    
    for(let i = 0; i < size; ++i) {
        const assembly = assemblies.add(i*4).readPointer();
        const image = {};
        image.assembly = assembly;
        image.handle = api.mono_assembly_get_image(assembly);
        image.name = api.mono_image_get_name(image.handle).readCString();
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

let dumpTo = "";
function dumpAssembly(assembly, data) {
    const api = getApi();
    if(api === null) return;
    const image = api.mono_assembly_get_image(assembly);
    const imageName = api.mono_image_get_name(image).readCString() + ".dll";
    const imageData = image.add(8).readPointer();
    const imageLength = image.add(0xc).readU32();
    na.dumpMem(imageData, imageLength, dumpTo + imageName);
}

const dumpCallback = new NativeCallback(dumpAssembly, 'void', ['pointer', 'pointer']);
function dump(path) {
    const api = getApi();
    if(api === null) return;
    dumpTo = path + "/";
    api.mono_assembly_foreach(dumpCallback, ptr(0));
}

function isStaticField(field) {
    const api = getApi();
    if(api === null) return;
    const offset = api.mono_field_get_offset(field);
    const attrs = api.mono_field_get_flags(field);
    
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
    const attrs = api.mono_field_get_flags(field);
    if(attrs & 0x40) return false;
    return true;
}

function isStaticMethod(method) {
    const api = getApi();
    if(api === null) return;
    const attrs = api.mono_method_get_flags(method, ptr(0));
    
    // Method_ATTRIBUTE_STATIC
    if(attrs & 0x10) return true;
    
    return false;
}

const il2CppException = Memory.alloc(Process.pointerSize);
function invokeWrapper() {
    let instance = arguments[0];
    const argcount = arguments.length - 1;
    if(instance.$handle !== undefined)
        instance = instance.$handle;
    else
        instance = ptr(instance);
    
    if(this.methodinfo === undefined) {
        this.methodinfo = cachedApi.mono_class_get_method_from_name(
            this.clz, Memory.allocUtf8String(this.name), argcount);
        if(argcount !== 0)
            this.params = Memory.alloc(Process.pointerSize * argcount);
        else
            this.params = ptr(0);
    }
    
    
    for(let i = 0; i < argcount; ++i) {
        let paramPtr = this.params.add(Process.pointerSize*i);
        let param = arguments[i+1];
        if(param.$handle !== undefined)
            paramPtr.writePointer(param.$handle);
        else if(typeof(param) === 'string') {
            paramPtr.writePointer(newString(param));
        }
        else
            paramPtr.writePointer(ptr(param));
    }
    try {
        let result = cachedApi.mono_runtime_invoke(this.methodinfo, instance, this.params, il2CppException); 
        let exception = il2CppException.readPointer();
        if(exception.isNull()) {
            return fromObject(result);
        }
        console.log(this.name, "exception");
        return result;
    } catch(e) {
        console.log(e);
        return null;
    }
}
let cachedClass = {};
function fromClass(clz) {
    const api = getApi();
    if(api === null) return;
    clz = ptr(clz);
    
    const tmpPtr = Memory.alloc(Process.pointerSize);
    const self = {};
    let curclz = clz;
    const cachedMethods = {};
    const cachedObjects = {};
    self.$vtable = api.mono_class_try_get_vtable(api.domain, clz);
    self.$classHandle = clz;
    self.$className = api.mono_class_get_name(clz).readCString();
    self.$namespace = api.mono_class_get_namespace(clz).readCString();
    while(!curclz.isNull()) {
        tmpPtr.writePointer(ptr(0));
        let field = api.mono_class_get_fields(curclz, tmpPtr);
        while(!field.isNull()) {
            const name = api.mono_field_get_name(field).readCString();
            if(isStaticField(field) && !self.hasOwnProperty(name)) {
                let curfield = field;
                Object.defineProperty(self, name, {
                    get: function () {
                        if(cachedObjects[name] === undefined) {
                            const fieldType = api.mono_field_get_type(curfield);
                            if(fieldType.isNull()) return null;
                            const fieldClz = api.mono_class_from_mono_type(fieldType);
                            if(fieldClz.isNull()) return null;
                            const valueSize = api.mono_class_value_size(fieldClz, ptr(0));
                            if(valueSize === 0) return null;
                            const valuePtr = Memory.alloc(valueSize);
                            if(self.$vtable.isNull())
                                self.$vtable = api.mono_class_try_get_vtable(api.domain, clz);
                            if(self.$vtable.isNull())
                                return null;
                            api.mono_field_static_get_value(self.$vtable, curfield, valuePtr);
                            const valueHandle = valuePtr.readPointer();
                            if(valueHandle.isNull()) return null;
                            if(!api.mono_class_is_valuetype(fieldClz)) {
                                cachedObjects[name] = fromObject(valueHandle);
                            }
                            else if(valueSize <= Process.pointerSize) {
                                cachedObjects[name] = valueHandle;
                            }
                            else 
                                cachedObjects[name] = valuePtr;
                        }
                        return cachedObjects[name];
                    },
                    set: function (value) {
                        const fieldType = api.mono_field_get_type(curfield);
                        if(fieldType.isNull()) return null;
                        const fieldClz = api.mono_class_from_mono_type(fieldType);
                        if(fieldClz.isNull()) return null;
                        const valueSize = api.mono_class_value_size(fieldClz, ptr(0));
                        // if(valueSize <= Process.pointerSize) {
                            // const valuePtr = Memory.alloc(Process.pointerSize);
                            // valuePtr.writePointer(ptr(value));
                            // api.mono_field_static_set_value(self.$vtable, curfield, valuePtr);
                        // } else {
                        api.mono_field_static_set_value(self.$vtable, curfield, value);
                        // }
                    }
                });
            }
            field = api.mono_class_get_fields(curclz, tmpPtr);
        }
        
        tmpPtr.writePointer(ptr(0));
        let method = api.mono_class_get_methods(curclz, tmpPtr);
        while(!method.isNull()) {
            const name = api.mono_method_get_name(method).readCString();
            let kname = name;
            // if(isStaticMethod(method) && !methods.hasOwnProperty(name)) {
            if(!self.hasOwnProperty(kname)) {
                let curmethod = method;
                Object.defineProperty(self, kname, {
                    get: function () {
                        if(cachedMethods[kname] === undefined) {
                            const wrapper = {};
                            wrapper.name = name;
                            wrapper.clz = clz;
                            cachedMethods[kname] = invokeWrapper.bind(wrapper);
                            
                            Object.defineProperty(cachedMethods[kname], "info", {
                                get: function() {
                                    if(wrapper.info === undefined) {
                                        const info = {};
                                        
                                        wrapper.info = info;
                                    }
                                    return wrapper.info;
                                },
                                set: function(value) {
                                    
                                }
                            });
                        }
                        
                        return cachedMethods[kname];
                    },
                    set: function (hook) {
                        const errorinfo = Memory.alloc(8);
                        eval(ef.interact);
                        // const fptr = api.mono_compile_method(curmethod);
                        const fptr = api.mono_jit_compile_method_jit_only(curmethod, errorinfo);
                        // const fptr = api.mono_jit_find_compiled_method(api.domain, curmethod);
                        if(fptr.isNull()) {
                            console.log(kname, "jit failed");
                            return;
                        }
                        if(hook instanceof Function) {
                            Interceptor.replace(fptr, hook);
                        } else {
                            Interceptor.attach(fptr, hook);
                        }
                    }
                });
            }
            method = api.mono_class_get_methods(curclz, tmpPtr);
        }
        curclz = api.mono_class_get_parent(curclz);
    }
    return self;
}

function fromObject(handle) {
    const api = getApi();
    if(api === null) return;
    if(typeof(handle) === 'number') handle = ptr(handle);
    if(handle.isNull()) return null;
    const clz = api.mono_object_get_class(handle);
    const self = fromClass(clz);
    let curclz = clz;
    let cachedMethods = {};
    self.$handle = handle;
    const tmpPtr = Memory.alloc(Process.pointerSize);
    while(!curclz.isNull()) {
        tmpPtr.writePointer(ptr(0));
        let field = api.mono_class_get_fields(curclz, tmpPtr);
        while(!field.isNull()) {
            const name = api.mono_field_get_name(field).readCString();
            if(isLocalField(field) && !self.hasOwnProperty(name)) {
                let curfield = field;
                Object.defineProperty(self, name, {
                    get: function () {
                        if(self.$handle.isNull()) return null;
                        const fieldType = api.mono_field_get_type(curfield);
                        if(fieldType.isNull()) return null;
                        const fieldClz = api.mono_class_from_mono_type(fieldType);
                        if(fieldClz.isNull()) return null;
                        const valuePtr = Memory.alloc(Process.pointerSize);
                        if( api.mono_class_is_valuetype(fieldClz)
                         && api.mono_class_value_size(fieldClz, ptr(0)) <= Process.pointerSize) {
                            api.mono_field_get_value(self.$handle, curfield, valuePtr);
                            return valuePtr.readPointer();
                        } else {
                            const valueHandle = api.mono_field_get_value_object(api.domain, curfield, self.$handle);
                            return fromObject(valueHandle);
                        }
                    },
                    set: function (value) {
                        if(self.$handle.isNull()) return;
                        const fieldType = api.mono_field_get_type(curfield);
                        if(fieldType.isNull()) return null;
                        const fieldClz = api.mono_class_from_mono_type(fieldType);
                        if(fieldClz.isNull()) return null;
                        // const valuePtr = Memory.alloc(Process.pointerSize);
                        // valuePtr.writePointer(ptr(value));
                        // api.mono_field_set_value(self.$handle, curfield, valuePtr);
                        api.mono_field_set_value(self.$handle, curfield, value);
                    }
                });
            }
            field = api.mono_class_get_fields(curclz, tmpPtr);
        }
        
        curclz = api.mono_class_get_parent(curclz);
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
    
    const clz = api.mono_class_from_name(image, namespace, name);
    if(clz.isNull()) return null;
    const result = fromClass(clz);
    return result;
}

function fromFullname(fullname) {
    // console.log("fromFullname", fullname);
    let splited = fullname.split(".");
    let name = splited[splited.length - 1];
    let namespace = splited.slice(0, splited.length - 1).join(".");
    let result = null;
    let images = enumerateImages();
    if(images) {
        images.forEach(function(image) {
            if(result === null) {
                result = fromName(image, namespace, name);
            }
        });
    }
    return result;
}

function readString(handle, maxlen) {
    let strhandle;
    if(handle.$handle !== undefined)
        strhandle = handle.$handle;
    else
        strhandle = ptr(handle);
    if(strhandle.isNull())
        return '';
    let length = strhandle.add(8).readInt();
    if(maxlen && length > maxlen) {
        return strhandle.add(0xc).readUtf16String(maxlen) + '...';
    }
    return strhandle.add(0xc).readUtf16String(length);
}

function perform(fn) {
    const api = getApi();
    if(api === null) {
        let attached = false;
        function doPerform(inited) {
            if(inited && !attached) {
                attached = true;
                let mono_init = Module.findExportByName("libmono.so", "mono_init");
                if(mono_init === null) mono_init = Module.findExportByName("libmonobdwgc-2.0.so", "mono_init");
                if(mono_init === null) mono_init = Module.findExportByName(null, "mono_init");
                if(mono_init === null) {
                    console.log("can't find mono_init");
                    return;
                }
                Interceptor.attach(mono_init, {
                    onLeave: function(retVal) {
                        fn();
                        Interceptor.revert(mono_init);
                        Interceptor.flush();
                    }
                });
                Interceptor.flush();
            }
        }
        na.libraryOnLoad("libmono.so", doPerform);
        na.libraryOnLoad("libmonobdwgc-2.0.so", doPerform);
        Interceptor.flush();
    }
    else {
        setImmediate(fn);
    }
}

module.exports = {
    dump,
    fromFullname,
    fromObject,
    perform
}