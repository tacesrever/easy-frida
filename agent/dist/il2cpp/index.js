"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const api_1 = require("./api");
const native_1 = require("../native");
;
/**
 * dump il2cpp symbols use https://github.com/tacesrever/Il2CppParser
 * require libparser compiled and pushed at /data/local/tmp/libparser.so
 */
function dump(addrfile, outname) {
    const libparser = Module.load('/data/local/tmp/libparser.so');
    const init = native_1.makefunction('libparser.so', 'init', 'pointer', ['string']);
    const dumpAll = native_1.makefunction('libparser.so', 'dumpAll', 'pointer', ['string', 'string']);
    const parser_log = new NativeCallback(function () {
        console.log(arguments[0].readCString());
    }, 'void', ['pointer']);
    libparser.getExportByName("parser_log").writePointer(parser_log);
    init(addrfile);
    dumpAll(outname + '.json', outname + '.h');
}
exports.dump = dump;
;
let cachedImages = [];
/**
 * enumerate loaded Images.
 */
function enumerateImages() {
    const api = api_1.getApi();
    let result = [];
    const domain = api.il2cpp_domain_get();
    const sizePtr = Memory.alloc(Process.pointerSize);
    const assemblies = api.il2cpp_domain_get_assemblies(domain, sizePtr);
    const size = sizePtr.readU32();
    if (cachedImages.length == size)
        return cachedImages;
    for (let i = 0; i < size; ++i) {
        const assembly = assemblies.add(i * Process.pointerSize).readPointer();
        const image = Object.create({});
        image.assembly = assembly;
        image.handle = api.il2cpp_assembly_get_image(assembly);
        image.name = api.il2cpp_image_get_name(image.handle).readCString();
        result.push(image);
    }
    cachedImages = result;
    return result;
}
exports.enumerateImages = enumerateImages;
function findImageByName(name) {
    const images = enumerateImages();
    for (let image of images) {
        if (image.name === name)
            return image;
    }
    return null;
}
exports.findImageByName = findImageByName;
function isStaticField(field) {
    const api = api_1.getApi();
    const offset = api.il2cpp_field_get_offset(field);
    const attrs = api.il2cpp_field_get_flags(field);
    // FIELD_ATTRIBUTE_STATIC
    if (attrs & 0x10)
        return true;
    // THREAD_STATIC_FIELD_OFFSET
    if (offset === -1)
        return true;
    return false;
}
function isLocalField(field) {
    const api = api_1.getApi();
    if (isStaticField(field))
        return false;
    const attrs = api.il2cpp_field_get_flags(field);
    if (attrs & 0x40)
        return false;
    return true;
}
function isStaticMethod(method) {
    const api = api_1.getApi();
    const attrs = api.il2cpp_method_get_flags(method, ptr(0));
    // Method_ATTRIBUTE_STATIC
    if (attrs & 0x10)
        return true;
    return false;
}
// TODO: per thread
const il2CppException = Memory.alloc(Process.pointerSize);
const exceptionMessage = Memory.alloc(0x1000);
const exceptionStack = Memory.alloc(0x4000);
class Il2cppMethod extends Function {
    constructor(parent, methodname) {
        super();
        this.parent = parent;
        this.methodname = methodname;
        this.methods = {};
        this.curmidx = -1;
        return new Proxy(this, {
            apply(target, thisArg, argumentsList) {
                return target.invoke(...argumentsList);
            }
        });
    }
    get declare() {
        return this.methods[this.curmidx].declare;
    }
    get ptr() {
        return this.methods[this.curmidx].functionPointer;
    }
    get offset() {
        return this.methods[this.curmidx].offset;
    }
    get fullname() {
        return this.methods[this.curmidx].fullname;
    }
    overload(argcount) {
        this.curmidx = argcount;
        return this;
    }
    addOverload(method) {
        const api = api_1.getApi();
        const argcount = api.il2cpp_method_get_param_count(method);
        const minfo = Object.create({});
        minfo.isStatic = isStaticMethod(method);
        minfo.method = method;
        minfo.argcount = argcount;
        minfo.functionPointer = method.readPointer();
        minfo.offset = minfo.functionPointer.sub(api.module.base);
        minfo.name = this.methodname;
        minfo.fullname = this.parent.$namespace + '.' + this.parent.$className + '.' + this.name;
        Object.defineProperty(minfo, "declare", {
            get: function () {
                let declare = "";
                if (this.isStatic)
                    declare = "static ";
                let buffer = api.il2cpp_type_get_name(api.il2cpp_method_get_return_type(this.method));
                declare += buffer.readCString();
                api.il2cpp_free(buffer);
                declare += ` ${this.name}(`;
                const argcount = api.il2cpp_method_get_param_count(this.method);
                for (let i = 0; i < argcount; ++i) {
                    buffer = api.il2cpp_type_get_name(api.il2cpp_method_get_param(this.method, i));
                    declare += buffer.readCString() + " ";
                    declare += api.il2cpp_method_get_param_name(this.method, i).readCString();
                    if (i !== argcount - 1) {
                        declare += ", ";
                    }
                    api.il2cpp_free(buffer);
                }
                declare += ");";
                return declare;
            }
        });
        if (this.curmidx === -1)
            this.curmidx = argcount;
        this.methods[argcount] = minfo;
    }
    invoke(...args) {
        const api = api_1.getApi();
        let objectPtr = ptr(0);
        const argcount = args.length;
        if (this.parent.$handle !== undefined)
            objectPtr = this.parent.$handle;
        const minfo = this.methods[argcount];
        let paramsBuffer;
        if (argcount !== 0)
            paramsBuffer = Memory.alloc(Process.pointerSize * argcount);
        else
            paramsBuffer = ptr(0);
        for (let i = 0; i < argcount; ++i) {
            let paramPtr = paramsBuffer.add(Process.pointerSize * i);
            let param = args[i];
            if (param.$handle instanceof NativePointer)
                paramPtr.writePointer(param.$handle);
            else if (typeof (param) === 'string') {
                paramPtr.writePointer(newString(param));
            }
            else
                paramPtr.writePointer(ptr(param));
        }
        try {
            let thread = api.il2cpp_thread_current();
            if (thread.isNull())
                thread = api.il2cpp_thread_attach(api.il2cpp_domain_get());
            else
                thread = null;
            const result = api.il2cpp_runtime_invoke(minfo.method, objectPtr, paramsBuffer, il2CppException);
            const exception = il2CppException.readPointer();
            if (thread !== null)
                api.il2cpp_thread_detach(thread);
            if (exception.isNull()) {
                return fromObject(result);
            }
            console.log(this.name, "exception:");
            api.il2cpp_format_exception(exception, exceptionMessage, 0x1000);
            api.il2cpp_format_stack_trace(exception, exceptionStack, 0x4000);
            console.log(exceptionMessage.readCString());
            console.log(exceptionStack.readCString());
            return result;
        }
        catch (e) {
            console.log(e);
            return null;
        }
    }
}
let cachedClass = {};
/**
 * get il2cpp class warpper by classinfo.
 */
function fromClass(handle) {
    const api = api_1.getApi();
    const tmpPtr = Memory.alloc(Process.pointerSize);
    const self = Object.create({});
    let curclz = handle;
    const cachedObjects = {};
    self.$classHandle = handle;
    self.$className = api.il2cpp_class_get_name(handle).readCString();
    self.$namespace = api.il2cpp_class_get_namespace(handle).readCString();
    while (!curclz.isNull()) {
        tmpPtr.writePointer(ptr(0));
        let field = api.il2cpp_class_get_fields(curclz, tmpPtr);
        while (!field.isNull()) {
            const name = api.il2cpp_field_get_name(field).readCString();
            if (isStaticField(field) && !self.hasOwnProperty(name)) {
                let curfield = field;
                Object.defineProperty(self, name, {
                    get: function () {
                        if (cachedObjects[name] === undefined) {
                            const fieldType = api.il2cpp_field_get_type(curfield);
                            const fieldClz = api.il2cpp_class_from_type(fieldType);
                            const valueSize = api.il2cpp_class_value_size(fieldClz, ptr(0));
                            const valuePtr = Memory.alloc(valueSize);
                            api.il2cpp_field_static_get_value(curfield, valuePtr);
                            if (!api.il2cpp_class_is_valuetype(fieldClz)) {
                                const valueHandle = valuePtr.readPointer();
                                cachedObjects[name] = fromObject(valueHandle);
                            }
                            else if (valueSize <= Process.pointerSize) {
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
                        if (valueSize <= Process.pointerSize) {
                            const valuePtr = Memory.alloc(Process.pointerSize);
                            valuePtr.writePointer(ptr(value));
                            api.il2cpp_field_static_set_value(curfield, valuePtr);
                        }
                        else {
                            api.il2cpp_field_static_set_value(curfield, value);
                        }
                    }
                });
            }
            field = api.il2cpp_class_get_fields(curclz, tmpPtr);
        }
        tmpPtr.writePointer(ptr(0));
        let method = api.il2cpp_class_get_methods(curclz, tmpPtr);
        while (!method.isNull()) {
            const name = api.il2cpp_method_get_name(method).readCString();
            let warpper = self[name];
            if (warpper === undefined) {
                warpper = new Il2cppMethod(self, name);
                self[name] = warpper;
            }
            warpper.addOverload(method);
            method = api.il2cpp_class_get_methods(curclz, tmpPtr);
        }
        curclz = api.il2cpp_class_get_parent(curclz);
    }
    return self;
}
/**
 * get il2cpp object warpper by object pointer.
 */
function fromObject(handle) {
    const api = api_1.getApi();
    if (typeof (handle) === 'number')
        handle = ptr(handle);
    if (handle.isNull())
        return null;
    const clz = api.il2cpp_object_get_class(handle);
    const self = fromClass(clz);
    let curclz = clz;
    self.$handle = handle;
    const tmpPtr = Memory.alloc(Process.pointerSize);
    while (!curclz.isNull()) {
        tmpPtr.writePointer(ptr(0));
        let field = api.il2cpp_class_get_fields(curclz, tmpPtr);
        while (!field.isNull()) {
            const name = api.il2cpp_field_get_name(field).readCString();
            if (isLocalField(field) && !self.hasOwnProperty(name)) {
                let curfield = field;
                Object.defineProperty(self, name, {
                    get: function () {
                        if (self.$handle.isNull())
                            return null;
                        const fieldType = api.il2cpp_field_get_type(curfield);
                        const fieldClz = api.il2cpp_class_from_type(fieldType);
                        if (api.il2cpp_class_is_valuetype(fieldClz)
                            && api.il2cpp_class_value_size(fieldClz, ptr(0)) <= Process.pointerSize) {
                            const valuePtr = Memory.alloc(Process.pointerSize);
                            api.il2cpp_field_get_value(self.$handle, curfield, valuePtr);
                            return valuePtr.readPointer();
                        }
                        else {
                            const valueHandle = api.il2cpp_field_get_value_object(curfield, self.$handle);
                            return fromObject(valueHandle);
                        }
                    },
                    set: function (value) {
                        if (self.$handle.isNull())
                            return;
                        const fieldType = api.il2cpp_field_get_type(curfield);
                        const fieldClz = api.il2cpp_class_from_type(fieldType);
                        if (api.il2cpp_class_is_valuetype(fieldClz)
                            && api.il2cpp_class_value_size(fieldClz, ptr(0)) <= Process.pointerSize) {
                            const valuePtr = Memory.alloc(Process.pointerSize);
                            valuePtr.writePointer(ptr(value));
                            api.il2cpp_field_set_value(self.$handle, curfield, valuePtr);
                        }
                        else {
                            api.il2cpp_field_set_value_object(self.$handle, curfield, ptr(value));
                        }
                    }
                });
            }
            field = api.il2cpp_class_get_fields(curclz, tmpPtr);
        }
        curclz = api.il2cpp_class_get_parent(curclz);
    }
    if (self.$className.substr(-2) === "[]") {
        self.$arraySize = handle.add(0xc).readU32();
        return new Proxy(self, {
            get: function (target, prop) {
                const idx = parseInt(prop);
                if (idx !== null && idx < target.$arraySize) {
                    // TODO: 64bit
                    return fromObject(target.$handle.add(0x10 + idx * 4).readPointer());
                }
                return target[prop];
            }
        });
    }
    else if (self.$className === "String" && self.$namespace === "System") {
        self.$str = readString(self.$handle);
    }
    return self;
}
exports.fromObject = fromObject;
/**
 * get il2cpp class warpper by it's image, namespace and name.
 */
function fromName(image, namespace, name) {
    const api = api_1.getApi();
    if (api === null)
        return null;
    if (typeof (namespace) === 'string')
        namespace = Memory.allocUtf8String(namespace);
    if (typeof (name) === 'string')
        name = Memory.allocUtf8String(name);
    if (typeof (image) === 'number')
        image = ptr(image);
    else if (typeof (image) === 'string') {
        let tmpimage = findImageByName(image);
        if (tmpimage) {
            image = tmpimage.handle;
        }
        else {
            console.log('can not find image', image);
            return null;
        }
    }
    else if (!(image instanceof NativePointer))
        image = image.handle;
    const clz = api.il2cpp_class_from_name(image, namespace, name);
    if (clz.isNull())
        return null;
    const result = fromClass(clz);
    return result;
}
exports.fromName = fromName;
/**
 * get il2cpp class warpper by it's fullname.
 */
function fromFullname(fullname) {
    let splited = fullname.split(".");
    let name = splited[splited.length - 1];
    let namespace;
    if (splited.length === 1)
        namespace = ptr(0);
    else
        namespace = splited.slice(0, splited.length - 1).join(".");
    let result = null;
    for (const image of enumerateImages()) {
        result = fromName(image, namespace, name);
        if (result !== null)
            return result;
    }
    return result;
}
exports.fromFullname = fromFullname;
/**
 * ensure current thread is attach to il2cpp main domain.
 */
function perform(callback) {
    const api = api_1.getApi();
    const thread = api.il2cpp_thread_attach(api.il2cpp_domain_get());
    callback();
    api.il2cpp_thread_detach(thread);
}
exports.perform = perform;
/**
 * read a .net string, if maxlen seted and str is too long, show ... after maxlen.
 */
function readString(handle, maxlen) {
    let strhandle;
    if (typeof (handle) === 'number' || typeof (handle) === 'bigint')
        strhandle = ptr(handle);
    else if (handle instanceof NativePointer)
        strhandle = handle;
    else
        strhandle = handle.$handle;
    if (strhandle.isNull())
        return '';
    let length = strhandle.add(2 * Process.pointerSize).readInt();
    if (maxlen && length > maxlen) {
        return strhandle.add(2 * Process.pointerSize + 4).readUtf16String(maxlen) + '...';
    }
    return strhandle.add(2 * Process.pointerSize + 4).readUtf16String(length);
}
exports.readString = readString;
/**
 * construct a .net string, return il2cpp object's pointer
 */
function newString(s) {
    const api = api_1.getApi();
    const sptr = Memory.allocUtf8String(s);
    return api.il2cpp_string_new(sptr);
}
exports.newString = newString;
;
let assemblies = null;
function enumerateAssemblies() {
    if (assemblies === null)
        assemblies = fromFullname("System.AppDomain").get_CurrentDomain().GetAssemblies();
    const result = [];
    for (let i = 0; i < assemblies.$arraySize; ++i) {
        const assembly = assemblies[i];
        const assemblyName = assembly.GetName();
        result.push({
            assembly: assembly,
            name: assemblyName.get_Name().$str
        });
    }
    return result;
}
exports.enumerateAssemblies = enumerateAssemblies;
function enumerateTypes(filter) {
    const result = {};
    enumerateAssemblies().forEach(item => {
        if (filter !== undefined && filter.indexOf(item.name) < 0)
            return;
        const assembly = item.assembly;
        const types = assembly.GetTypes();
        console.log(item.name, "total:", types.$arraySize);
        for (let i = 0; i < types.$arraySize; ++i) {
            if (i % 5000 === 0)
                console.log(i, "...");
            const type = types[i];
            let namespace = type.get_Namespace();
            if (namespace !== null)
                namespace = namespace.$value;
            else
                namespace = "_";
            const name = type.get_Name().$value;
            if (result[namespace] === undefined)
                result[namespace] = [];
            result[namespace].push(name);
        }
    });
    return result;
}
exports.enumerateTypes = enumerateTypes;
//# sourceMappingURL=index.js.map