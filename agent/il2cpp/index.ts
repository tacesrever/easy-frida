
import { getApi } from './api';
import { importfunc, symbolName } from '../native';
import { readFile } from '../linux';

interface Image {
    name: string | null
    handle: NativePointer
    assembly: NativePointer
};

interface Il2cppClass {
    [index: string]: any
    $classHandle: NativePointer
    $className: string | null
    $namespace: string | null
}

interface Il2cppObject extends Il2cppClass {
    $handle: NativePointer
    $arraySize?: number
    $arrayPtr?: NativePointer
    $str?: string
}

/**
 * dump il2cpp symbols use https://github.com/tacesrever/Il2CppParser  
 * require libparser compiled and pushed at /data/local/tmp/libparser.so
 */
export function dump(addrfile: string, outname: string) {
    const libparser = Module.load('/data/local/tmp/libparser.so');
    
    const init = importfunc('libparser.so', 'init', 'pointer', ['string']);
    const dumpAll = importfunc('libparser.so', 'dumpAll', 'pointer', ['string', 'string']);
    
    const parser_log = new NativeCallback(function() {
        console.log(arguments[0].readCString());
    }, 'void', ['pointer']);
    
    libparser.getExportByName("parser_log").writePointer(parser_log);
    
    init(addrfile);
    dumpAll(outname+'.json', outname+'.h');
};

let cachedImages: Image[] = [];
/**
 * enumerate loaded Images.
 */
export function enumerateImages() {
    const api = getApi();
    let result: Image[] = [];
    
    const domain = api.il2cpp_domain_get();
    const sizePtr = Memory.alloc(Process.pointerSize);
    
    const assemblies = api.il2cpp_domain_get_assemblies(domain, sizePtr);
    const size = sizePtr.readU32();
    if(cachedImages.length == size) return cachedImages;
    
    for(let i = 0; i < size; ++i) {
        const assembly = assemblies.add(i*Process.pointerSize).readPointer();
        const image: Image = Object.create({});
        image.assembly = assembly;
        image.handle = api.il2cpp_assembly_get_image(assembly);
        image.name = api.il2cpp_image_get_name(image.handle).readCString();
        result.push(image);
    }
    cachedImages = result;
    return result;
}
export function findImageByName(name: string) {
    const images = enumerateImages();
    for(let image of images) {
        if(image.name === name) return image;
    }
    return null;
}
function isStaticField(field: NativePointer) {
    const api = getApi();
    const offset = api.il2cpp_field_get_offset(field);
    const attrs = api.il2cpp_field_get_flags(field);
    
    // FIELD_ATTRIBUTE_STATIC
    if(attrs & 0x10) return true;
    // THREAD_STATIC_FIELD_OFFSET
    if(offset === -1) return true;
    
    return false;
}

function isLocalField(field: NativePointer) {
    const api = getApi();
    if(isStaticField(field)) return false;
    const attrs = api.il2cpp_field_get_flags(field);
    if(attrs & 0x40) return false;
    return true;
}

function isStaticMethod(method: NativePointer) {
    const api = getApi();
    const attrs = api.il2cpp_method_get_flags(method, ptr(0));
    
    // Method_ATTRIBUTE_STATIC
    if(attrs & 0x10) return true;
    
    return false;
}

export function getMethodString(method: NativePointer) {
    const api = getApi();
    let declare: string = "";
    const clz = api.il2cpp_method_get_class(method);
    const clzName = api.il2cpp_class_get_name(clz).readCString() as string;
    const clzNamespace = api.il2cpp_class_get_namespace(clz).readCString() as string;
    const funcName = api.il2cpp_method_get_name(method).readCString() as string;
    if(isStaticMethod(method)) declare = "static ";
    let buffer = api.il2cpp_type_get_name(api.il2cpp_method_get_return_type(method));
    declare += buffer.readCString();
    api.il2cpp_free(buffer);
    declare += ` ${clzNamespace}.${clzName}.${funcName}(`;
    const argcount = api.il2cpp_method_get_param_count(method);
    for(let i = 0; i < argcount; ++i) {
        buffer = api.il2cpp_type_get_name(api.il2cpp_method_get_param(method, i));
        declare += buffer.readCString() + " ";
        declare += api.il2cpp_method_get_param_name(method, i).readCString();
        if(i !== argcount - 1) {
            declare += ", ";
        }
        api.il2cpp_free(buffer);
    }
    declare += ")";
    return declare;
}

// TODO: per thread
const il2CppException = Memory.alloc(Process.pointerSize);
const exceptionMessage = Memory.alloc(0x1000);
const exceptionStack = Memory.alloc(0x4000);

interface Il2cppMethodInfo {
    method: NativePointer
    isStatic: boolean
    argcount: number
    functionPointer: NativePointer
    offset: NativePointer
    name: string
    fullname: string
    declare: string
}

class Il2cppMethod extends Function {
    methods: {
        [index: string]: Il2cppMethodInfo
    } = {}
    curmidx: number = -1
    constructor(public parent: Il2cppClass, public methodname: string) {
        super();
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

    overload(this: Il2cppMethod, argcount: number) {
        this.curmidx = argcount;
        return this;
    }

    addOverload(this: Il2cppMethod, method: NativePointer) {
        const api = getApi();
        const argcount = api.il2cpp_method_get_param_count(method);
        const minfo: Il2cppMethodInfo = Object.create({});
        minfo.isStatic = isStaticMethod(method);
        minfo.method = method;
        minfo.argcount = argcount;
        minfo.functionPointer = method.readPointer();
        minfo.offset = minfo.functionPointer.sub(api.module.base);
        minfo.name = this.methodname;
        minfo.fullname = this.parent.$namespace + '.' + this.parent.$className + '.' + this.name;
        Object.defineProperty(minfo, "declare", {
            get: function() {
                let declare: string = "";
                if(this.isStatic) declare = "static ";
                let buffer = api.il2cpp_type_get_name(api.il2cpp_method_get_return_type(this.method));
                declare += buffer.readCString();
                api.il2cpp_free(buffer);
                declare += ` ${this.name}(`;
                const argcount = api.il2cpp_method_get_param_count(this.method);
                for(let i = 0; i < argcount; ++i) {
                    buffer = api.il2cpp_type_get_name(api.il2cpp_method_get_param(this.method, i));
                    declare += buffer.readCString() + " ";
                    declare += api.il2cpp_method_get_param_name(this.method, i).readCString();
                    if(i !== argcount - 1) {
                        declare += ", ";
                    }
                    api.il2cpp_free(buffer);
                }
                declare += ");";
                return declare;
            }
        });
        if(this.curmidx === -1) this.curmidx = argcount;
        this.methods[argcount] = minfo;
    }

    invoke(this: Il2cppMethod, ...args: any[]) {
        const api = getApi();
        let objectPtr = ptr(0);
        const argcount = args.length;
        if(this.parent.$handle !== undefined)
            objectPtr = this.parent.$handle;
        const minfo = this.methods[argcount];
        let paramsBuffer;
        if(argcount !== 0)
            paramsBuffer = Memory.alloc(Process.pointerSize * argcount);
        else
            paramsBuffer = ptr(0);
        
        for(let i = 0; i < argcount; ++i) {
            let paramPtr = paramsBuffer.add(Process.pointerSize*i);
            let param = args[i];
            if(param.$handle instanceof NativePointer)
                paramPtr.writePointer(param.$handle);
            else if(typeof(param) === 'string') {
                paramPtr.writePointer(newString(param));
            }
            else
                paramPtr.writePointer(ptr(param));
        }
        try {
            let thread: NativePointer | null = api.il2cpp_thread_current();
            if(thread.isNull())
                thread = api.il2cpp_thread_attach(api.il2cpp_domain_get());
            else thread = null;
            const result = api.il2cpp_runtime_invoke(
                    minfo.method, objectPtr, paramsBuffer, il2CppException); 
            const exception = il2CppException.readPointer();
            if(thread !== null) api.il2cpp_thread_detach(thread);
            if(exception.isNull()) {
                return fromObject(result);
            }
            console.log(this.name, "exception:");
            api.il2cpp_format_exception(exception, exceptionMessage, 0x1000);
            api.il2cpp_format_stack_trace(exception, exceptionStack, 0x4000);
            console.log(exceptionMessage.readCString());
            console.log(exceptionStack.readCString());
            return result;
        } catch(e) {
            console.log(e);
            return null;
        }
    }
}
let cachedClass = {};
/**
 * get il2cpp class warpper by classinfo.  
 */
function fromClass(handle: NativePointer): Il2cppClass {
    const api = getApi();
    const tmpPtr = Memory.alloc(Process.pointerSize);
    const self: Il2cppClass = Object.create({});
    let curclz = handle;
    const cachedObjects: any = {};
    self.$classHandle = handle;
    self.$className = api.il2cpp_class_get_name(handle).readCString();
    self.$namespace = api.il2cpp_class_get_namespace(handle).readCString();
    while(!curclz.isNull()) {
        tmpPtr.writePointer(ptr(0));
        let field = api.il2cpp_class_get_fields(curclz, tmpPtr);
        while(!field.isNull()) {
            const name = api.il2cpp_field_get_name(field).readCString() as string;
            if(isStaticField(field) && !self.hasOwnProperty(name)) {
                let curfield = field;
                Object.defineProperty(self, name, {
                    get: function () {
                        if(cachedObjects[name] === undefined) {
                            const fieldType = api.il2cpp_field_get_type(curfield);
                            const fieldClz = api.il2cpp_class_from_type(fieldType);
                            const valueSize = api.il2cpp_class_value_size(fieldClz, ptr(0));
                            const valuePtr = Memory.alloc(valueSize);
                            if(valuePtr.isNull()) return undefined;
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
            const name = api.il2cpp_method_get_name(method).readCString() as string;
            let warpper = self[name];
            if(warpper === undefined) {
                warpper = new Il2cppMethod(self, name);
                self[name] = warpper;
            }
            if(warpper instanceof Il2cppMethod) {
                warpper.addOverload(method);
            } else {
                warpper = new Il2cppMethod(self, name);
                self["_"+name] = warpper;
            }
            
            method = api.il2cpp_class_get_methods(curclz, tmpPtr);
        }
        curclz = api.il2cpp_class_get_parent(curclz);
    }
    return self;
}
/**
 * get il2cpp object warpper by object pointer.  
 */
export function fromObject(handle: NativePointer | number): Il2cppObject | null {
    const api = getApi();
    if(typeof(handle) === 'number') handle = ptr(handle);
    if(handle.isNull()) return null;
    const clz = api.il2cpp_object_get_class(handle);
    const self = fromClass(clz);
    let curclz = clz;
    self.$handle = handle;
    const tmpPtr = Memory.alloc(Process.pointerSize);
    while(!curclz.isNull()) {
        tmpPtr.writePointer(ptr(0));
        let field = api.il2cpp_class_get_fields(curclz, tmpPtr);
        while(!field.isNull()) {
            const name = api.il2cpp_field_get_name(field).readCString() as string;
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
    if(self.$className.substr(-2) === "[]") {
        self.$arraySize = handle.add(3*Process.pointerSize).readU32();
        self.$arrayPtr = handle.add(4*Process.pointerSize);

        return new Proxy(<Il2cppObject>self, {
            get: function(target, prop) {
                const idx = parseInt(prop as string);
                if(idx !== null && idx < <number>target.$arraySize) {
                    return fromObject(target.$handle.add(4*Process.pointerSize+idx*Process.pointerSize).readPointer());
                }
                return target[prop as string];
            }
        });
    }
    else if(self.$className === "String" && self.$namespace === "System") {
        self.$str = readString(self.$handle);
    }
    return <Il2cppObject>self;
}
/**
 * get il2cpp class warpper by it's image, namespace and name.  
 */
export function fromName(
        image: Image | string | NativePointer | number,
        namespace: string | NativePointer,
        name: string | NativePointer) {
    const api = getApi();
    if(api === null) return null;
    if(typeof(namespace) === 'string') namespace = Memory.allocUtf8String(namespace);
    if(typeof(name) === 'string') name = Memory.allocUtf8String(name);
    if(typeof(image) === 'number') image = ptr(image);
    else if(typeof(image) === 'string') {
        let tmpimage = findImageByName(image);
        if(tmpimage) {
            image = tmpimage.handle;
        }
        else {
            console.log('can not find image', image);
            return null;
        }
    }
    else if(!(image instanceof NativePointer)) image = image.handle;
    const clz = api.il2cpp_class_from_name(image, namespace, name);
    if(clz.isNull()) return null;
    const result = fromClass(clz);
    return result;
}
/**
 * get il2cpp class warpper by it's fullname.  
 */
export function fromFullname(fullname: string) {
    let splited = fullname.split(".");
    let name = splited[splited.length - 1];
    let namespace;
    if(splited.length === 1) namespace = "";
    else namespace = splited.slice(0, splited.length - 1).join(".");
    let result: Il2cppClass | null = null;
    for(const image of enumerateImages()) {
        result = fromName(image, namespace, name);
        if(result !== null) return result;
    }
    return result;
}
/**
 * ensure current thread is attach to il2cpp main domain.
 */
export function perform(callback: () => void) {
    const api = getApi();
    const thread = api.il2cpp_thread_attach(api.il2cpp_domain_get());
    callback();
    api.il2cpp_thread_detach(thread);
}
/**
 * read a .net string, if maxlen seted and str is too long, show ... after maxlen.
 */
export function readString(handle: number | NativePointer | {$handle: NativePointer}, maxlen?: number) {
    let strhandle: NativePointer;
    if(typeof(handle) === 'number' || typeof(handle) === 'bigint')
        strhandle = ptr(handle);
    else if(handle instanceof NativePointer)
        strhandle = handle;
    else
        strhandle = handle.$handle;
    if(strhandle.isNull()) return '';
    let length = strhandle.add(2*Process.pointerSize).readInt();
    if(maxlen && length > maxlen) {
        return strhandle.add(2*Process.pointerSize+4).readUtf16String(maxlen) + '...';
    }
    return strhandle.add(2*Process.pointerSize+4).readUtf16String(length);
}
/**
 * construct a .net string, return il2cpp object's pointer
 */
export function newString(s: string) {
    const api = getApi();
    const sptr = Memory.allocUtf8String(s);
    return api.il2cpp_string_new(sptr);
};

let assemblies: any = null;
export function enumerateAssemblies() {
    if(assemblies === null)
        assemblies = fromFullname("System.AppDomain").get_CurrentDomain().GetAssemblies();
    const result: {
        assembly: Il2cppObject,
        name: string
    }[] = [];
    for(let i = 0; i < assemblies.$arraySize; ++i) {
        const assembly = assemblies[i];
        const assemblyName = assembly.GetName();
        result.push({
            assembly: assembly as Il2cppObject,
            name: assemblyName.get_Name().$str as string
        });
    }
    return result;
}

export function enumerateTypes(filter: string[]) {
    const result: {
        [index: string]: string[]
    } = {};
    enumerateAssemblies().forEach(item => {
        if(filter !== undefined && filter.indexOf(item.name) < 0) return;
        const assembly = item.assembly;
        const types = assembly.GetTypes();
        console.log(item.name, "total:", types.$arraySize);
        for(let i = 0; i < types.$arraySize; ++i) {
            if(i % 5000 === 0) console.log(i, "...");
            const type = types[i];
            let namespace = type.get_Namespace();
            if(namespace !== null) namespace = namespace.$value;
            else namespace = "_";
            const name = type.get_Name().$value;
            if(result[namespace] === undefined) result[namespace] = [];
            result[namespace].push(name);
        }
    });
    return result;
}

const backtraceCode = `
#include "glib.h"
#include "string.h"
#include "stdlib.h"

extern void __android_log_print(int level, const char* tag, const char* fmt, ...);
#define log(...) __android_log_print(4, "frida-ILBT", __VA_ARGS__);

typedef size_t pointerValue;
typedef int32_t TypeDefinitionIndex;

typedef struct Il2CppImage {
    const char* name;
    const char* nameNoExt;
    uint32_t assembly;

    TypeDefinitionIndex typeStart;
    uint32_t typeCount;
} Il2CppImage;

extern pointerValue Il2cppBase;
extern pointerValue il2cpp_domain_get();
extern pointerValue* il2cpp_domain_get_assemblies(pointerValue domain, size_t *size);
extern Il2CppImage* il2cpp_assembly_get_image(pointerValue assembly);
extern pointerValue il2cpp_class_get_methods(pointerValue klass, void** iter);
extern pointerValue GetTypeInfoFromTypeDefinitionIndex(TypeDefinitionIndex idx);

extern pointerValue* method_ptr_info_map;
extern unsigned int* method_order;
extern unsigned int method_idx;
extern size_t method_count;

extern pointerValue* map_p;

void foreach_method(void (*fn)(pointerValue)) {
    pointerValue domain, klass, method, method_ptr;
    size_t i, type_idx, type_idx_end, assembly_count;
    Il2CppImage* image;
    void* iter;

    domain = il2cpp_domain_get();
    pointerValue* assemblies = il2cpp_domain_get_assemblies(domain, &assembly_count);
    for(i = 0; i < assembly_count; ++i) {
        image = il2cpp_assembly_get_image(assemblies[i]);
        type_idx_end = image->typeStart + image->typeCount;
        for(type_idx = image->typeStart; type_idx < type_idx_end; ++type_idx) {
            klass = GetTypeInfoFromTypeDefinitionIndex(type_idx);
            iter = NULL;
            method = il2cpp_class_get_methods(klass, &iter);
            while (method != NULL) {
                if(*(pointerValue*)method != NULL) fn(method);
                method = il2cpp_class_get_methods(klass, &iter);
            }
        }
    }
}

void count(pointerValue method) {
    method_count++;
}

void sort_insert(pointerValue method) {
    pointerValue key = *(pointerValue*)method;
    pointerValue tmp_key;
    pointerValue *start_p, *end_p;
    unsigned int range, move_len;
    if(*map_p > key) {
        map_p--;
        *map_p = key;
        map_p[method_count] = method_idx;
    } else {
        start_p = map_p;
        end_p = &method_ptr_info_map[method_count];
        range = end_p - start_p;
        while (range > 1) {
            if(start_p[range/2] < key) {
                start_p = &start_p[range/2];
            } else {
                end_p = &start_p[range/2];
            }
            range = end_p - start_p;
        }
        move_len = ((start_p - map_p) + 1) * sizeof(gpointer);
        memmove(map_p - 1, map_p, move_len);
        memmove(&map_p[method_count - 1], &map_p[method_count], move_len);
        *start_p = key;
        start_p[method_count] = method_idx;
        map_p--;
    }
    method_idx++;
}

void load_method(pointerValue method) {
    method_ptr_info_map[method_order[method_idx]] = *(pointerValue*)method;
    method_ptr_info_map[method_order[method_idx] + method_count] = method;
    method_idx++;
}

void parse() {
    unsigned int i;
    method_count = 0;
    foreach_method(count);
    log("method_count: %d", method_count);
    if(method_ptr_info_map) g_free(method_ptr_info_map);
    method_ptr_info_map = g_malloc(2 * method_count * sizeof(gpointer));
    map_p = &method_ptr_info_map[method_count];
    method_ptr_info_map[method_count] = (size_t)-1;
    log("sorting...");
    foreach_method(sort_insert);
    method_order = g_malloc(method_count * sizeof(unsigned int));
    for(i = 0; i < method_count; ++i) {
        method_order[method_ptr_info_map[method_count + i]] = i;
    }
    log("loading...");
    method_idx = 0;
    foreach_method(load_method);
    log("done.");
}

void load() {
    method_idx = 0;
    if(method_ptr_info_map) g_free(method_ptr_info_map);
    method_ptr_info_map = g_malloc(2 * method_count * sizeof(gpointer));
    foreach_method(load_method);
}

pointerValue get_method_info(pointerValue address) {
    pointerValue *start_p, *end_p;
    unsigned int range;
    start_p = method_ptr_info_map;
    end_p = method_ptr_info_map + method_count;
    range = end_p - start_p;
    while (range > 1) {
        if(start_p[range/2] < address) {
            start_p = &start_p[range/2];
        } else {
            end_p = &start_p[range/2];
        }
        range = end_p - start_p;
    }
    return start_p[method_count];
}
`;

let btModule: CModule = null;

/**  
 * 

*/
function findGetTypeInfoFromTypeDefinitionIndex() {
    if(!(["arm", "arm64"].includes(Process.arch))) return null;
    type InstType = ArmInstruction | Arm64Instruction;
    const libil2cpp = Process.findModuleByName("libil2cpp.so");
    const il2cpp_type_get_class_or_element_class = libil2cpp.findExportByName("il2cpp_type_get_class_or_element_class");
    let inst = <InstType>Instruction.parse(il2cpp_type_get_class_or_element_class);
    while(inst.groups.includes("jump")) {
        inst = <InstType>Instruction.parse(ptr(<number>inst.operands[0].value));
    }
    let last_inst = inst;
    let call_counter = 0;
    let last_called;
    inst = <InstType>Instruction.parse(inst.next);
    while(call_counter < 3) {
        if(inst.mnemonic === 'b') {
            if(last_called !== undefined && inst.operands[0].value !== last_called) {
                return ptr(<number>inst.operands[0].value);
            }
            
            call_counter += 1;
            last_called = inst.operands[0].value;
        }
        last_inst = inst;
        inst = <InstType>Instruction.parse(inst.next);
    }
}

function backtraceInit() {
    const linkSymbols: CSymbols = {};
    const libil2cpp = Process.findModuleByName("libil2cpp.so");

    linkSymbols["__android_log_print"] = Module.findExportByName(null, "__android_log_print");
    linkSymbols["il2cpp_domain_get"] = libil2cpp.findExportByName("il2cpp_domain_get");
    linkSymbols["il2cpp_assembly_get_image"] = libil2cpp.findExportByName("il2cpp_assembly_get_image");
    linkSymbols["il2cpp_class_get_methods"] = libil2cpp.findExportByName("il2cpp_class_get_methods");
    linkSymbols["GetTypeInfoFromTypeDefinitionIndex"] = findGetTypeInfoFromTypeDefinitionIndex();
    linkSymbols["il2cpp_domain_get_assemblies"] = libil2cpp.findExportByName("il2cpp_domain_get_assemblies");
    
    linkSymbols["Il2cppBase"] = Memory.alloc(Process.pointerSize);
    linkSymbols["Il2cppBase"].writePointer(libil2cpp.base);
    linkSymbols["method_ptr_info_map"] = Memory.alloc(Process.pointerSize);
    linkSymbols["method_order"] = Memory.alloc(Process.pointerSize);
    linkSymbols["method_idx"] = Memory.alloc(Process.pointerSize);
    linkSymbols["method_count"] = Memory.alloc(Process.pointerSize);
    linkSymbols["map_p"] = Memory.alloc(Process.pointerSize);
    btModule = new CModule(backtraceCode, linkSymbols);
    
    const fcmdline = readFile("/proc/self/cmdline");
    const appname = fcmdline.base.readCString();
    const savefile = `/data/data/${appname}/files/ILBT_method_order`;
    const access = importfunc(null, "access", 'int', ['string', 'int']);
    if(access(savefile, 4) === 0) {
        const method_order = readFile(savefile);
        globalThis._method_order = method_order;
        linkSymbols["method_order"].writePointer(method_order.base);
        linkSymbols["method_count"].writePointer(ptr(method_order.size / 4));
        const load = new NativeFunction(btModule.load, 'void', []);
        load();
    }
    else {
        const parse = new NativeFunction(btModule.parse, 'void', []);
        console.log();
        parse();
        const out = new File(savefile, "wb");
        const data = btModule.method_order.readPointer().readByteArray(btModule.method_count.readUInt()*4);
        out.write(data);
        out.close();
    }
    const get_method_info = new NativeFunction(btModule.get_method_info, 'pointer', ['pointer']);
    Object.defineProperty(btModule, "getMethodInfo", { value: get_method_info });
}

export function il2cppSymbolName(addr: NativePointer) {
    const m = Process.findModuleByAddress(addr);
    if(m && m.name === "libil2cpp.so") {
        const method: NativePointer = btModule.getMethodInfo(addr);
        const method_ptr = method.readPointer();
        if(!method.isNull()) return `libil2cpp.so!${method_ptr.sub(m.base)} ${getMethodString(method)}+${addr.sub(method_ptr)}`;
    }
    return symbolName(addr);
}

export function showBacktrace(context?: CpuContext) {
    if(btModule === null) backtraceInit();
    let bt = Thread.backtrace(context, Backtracer.ACCURATE).map(il2cppSymbolName).join("\n\t");
    console.log('\t' + bt);
}