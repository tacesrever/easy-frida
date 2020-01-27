
let cachedApi = null;
const ef = require("./easy_frida.js");
const na = require("./native.js");
const android = require("./android.js");

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
    il2cpp_format_exception: ['pointer', ['pointer', 'pointer', 'int']], 
    il2cpp_format_stack_trace: ['pointer', ['pointer', 'pointer', 'int']], 
    il2cpp_get_exception_argument_null: ['pointer', ['pointer']],
    il2cpp_object_new: ['pointer', ['pointer']],
}
function getApi() {
    if (cachedApi !== null) {
        return cachedApi;
    }
    const tempApi = {};
    let libil2cpp = Process.findModuleByName("libil2cpp.so");
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

const il2CppException = Memory.alloc(Process.pointerSize);
const exceptionMessage = Memory.alloc(0x1000);
const exceptionStack = Memory.alloc(0x4000);
function invokeWrapper() {
    let instance = arguments[0];
    const argcount = arguments.length - 1;
    if(instance.$handle !== undefined)
        instance = instance.$handle;
    else
        instance = ptr(instance);
    
    if(this.methodinfo === undefined) {
        this.methodinfo = cachedApi.il2cpp_class_get_method_from_name(
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
            console.log(param);
            paramPtr.writePointer(newString(param));
        }
        else
            paramPtr.writePointer(ptr(param));
    }
    try {
        let result = cachedApi.il2cpp_runtime_invoke(this.methodinfo, instance, this.params, il2CppException); 
        let exception = il2CppException.readPointer();
        if(exception.isNull()) {
            return fromObject(result);
        }
        console.log(this.name, "exception:");
        cachedApi.il2cpp_format_exception(exception, exceptionMessage, 0x1000);
        cachedApi.il2cpp_format_stack_trace(exception, exceptionStack, 0x4000);
        console.log(exceptionMessage.readCString());
        console.log(exceptionStack.readCString());
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
    self.$classHandle = clz;
    self.$className = api.il2cpp_class_get_name(clz).readCString();
    self.$namespace = api.il2cpp_class_get_namespace(clz).readCString();
    while(!curclz.isNull()) {
        tmpPtr.writePointer(ptr(0));
        let field = api.il2cpp_class_get_fields(curclz, tmpPtr);
        while(!field.isNull()) {
            const name = api.il2cpp_field_get_name(field).readCString();
            if(isStaticField(field) && !self.hasOwnProperty(name)) {
                let curfield = field;
                Object.defineProperty(self, name, {
                    get: function () {
                        if(cachedObjects[name] === undefined) {
                            const fieldType = api.il2cpp_field_get_type(curfield);
                            const fieldClz = api.il2cpp_class_from_type(fieldType);
                            const valueSize = api.il2cpp_class_value_size(fieldClz, ptr(0));
                            const valuePtr = Memory.alloc(valueSize);
                            api.il2cpp_field_static_get_value(curfield, valuePtr);
                            if(!api.il2cpp_class_is_valuetype(fieldClz)) {
                                const valueHandle = valuePtr.readPointer();
                                cachedObjects[name] = fromObject(valueHandle);
                            }
                            else if(valueSize <= Process.pointerSize) {
                                cachedObjects[name] = valuePtr.readPointer();
                            } 
                            else 
                                cachedObjects[name] = valuePtr;
                        }
                        return cachedObjects[name];
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
            let kname = name;
            if(self.hasOwnProperty(kname)) {
                const argcount = api.il2cpp_method_get_param_count(method);
                kname += `_${argcount}`;
            }
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
                            Object.defineProperty(cachedMethods[kname], "ptr", {
                                value: curmethod.readPointer()
                            });
                            Object.defineProperty(cachedMethods[kname], "info", {
                                get: function() {
                                    if(wrapper.info === undefined) {
                                        const info = {};
                                        const lib = Process.findModuleByName("libil2cpp.so");
                                        info.offset = cachedMethods[kname].ptr.sub(lib.base);
                                        info.fullname = `${self.$namespace}.${self.$className}.${name}`;
                                        let type = api.il2cpp_method_get_return_type(curmethod);
                                        let buffer = api.il2cpp_type_get_name(type);
                                        if(isStaticMethod(curmethod))
                                            info.type = "static ";
                                        else
                                            info.type = "";
                                        info.type += buffer.readCString();
                                        info.type += ` ${name}(`;
                                        api.il2cpp_free(buffer);
                                        const argcount = api.il2cpp_method_get_param_count(curmethod);
                                        for(let i = 0; i < argcount; ++i) {
                                            type = api.il2cpp_method_get_param(curmethod, i);
                                            buffer = api.il2cpp_type_get_name(type);
                                            info.type += buffer.readCString() + " ";
                                            info.type += api.il2cpp_method_get_param_name(curmethod, i).readCString();
                                            if(i !== argcount - 1) {
                                                info.type += ", ";
                                            }
                                            api.il2cpp_free(buffer);
                                        }
                                        info.type += ");";
                                        
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
    if(typeof(handle) === 'number') handle = ptr(handle);
    if(handle.isNull()) return null;
    const clz = api.il2cpp_object_get_class(handle);
    const self = fromClass(clz);
    let curclz = clz;
    let cachedMethods = {};
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
                        if(self.$handle.isNull()) return null;
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
                        if(self.$handle.isNull()) return;
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

// function findObjectByName(fullname) {
    // const api = getApi();
    // if(api === null) return;
    
    // const clz = fromFullname(fullname);
    // if(clz === null) return null;
    // const type = api.il2cpp_class_get_type(clz);
    // const obj = api.il2cpp_type_get_object(type);
    // if(obj === null) return null;
    // return fromObject(obj);
// }

function perform(fn) {
    const api = getApi();
    if(api === null) {
        let attached = false;
        android.libraryOnLoad("libil2cpp.so", function(inited) {
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
        setImmediate(fn);
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

function dump(addrfile, output) {
    Module.load("/data/local/tmp/libparser.so");
    na.modules.parser.init = ['pointer', ['string']];
    na.modules.parser.dumpAll = ['pointer', ['string', 'string']];
    
    const parser_log = new NativeCallback(function() {
        console.log(arguments[0].readCString());
    }, 'void', ['pointer']);
    
    na.modules.parser.parser_log = parser_log;
    
    na.modules.parser.init(addrfile);
    na.modules.parser.dumpAll(output+'.json', output+'.h');
}

function newString(s) {
    const api = getApi();
    if(api === null) return;
    const sptr = Memory.allocUtf8String(s);
    return api.il2cpp_string_new(sptr);
}

function readString(handle, maxlen) {
    let strhandle;
    if(handle.$handle !== undefined)
        strhandle = handle.$handle;
    else
        strhandle = ptr(handle);
    if(strhandle.isNull())
        return '';
    let length = strhandle.add(2*Process.pointerSize).readInt();
    if(maxlen && length > maxlen) {
        return strhandle.add(2*Process.pointerSize+4).readUtf16String(maxlen) + '...';
    }
    return strhandle.add(2*Process.pointerSize+4).readUtf16String(length);
}

// function backtrace() {
    // use android.backtrace and methodinfo
// }

module.exports = {
    dump,
    getApi,
    getDomain,
    enumerateImages,
    findImageByName,
    fromObject,
    fromName,
    fromFullname,
    perform,
    readString,
    newString
}