
const easy_frida = require("./easy_frida.js");

function backtrace( context ) {
    let bt = Thread.backtrace(context, Backtracer.ACCURATE)
        .map(symbolName).join("\n\t");
    console.log('\t' + bt);
}
exports.backtrace = backtrace;

function hdump(addr, n) {
    if(n) {
        console.log(hexdump(ptr(addr), {length:n}));
    } else {
        console.log(hexdump(ptr(addr)));
    }
}
exports.hdump = hdump;

//warpper for NativeFunction, add 'string' type.
function makefunction(liborAddr, name, retType, argList, options) {
    let faddr, argType = [], nativef;
    
    if (liborAddr == null || typeof liborAddr == 'string') {
        faddr = Module.findExportByName(liborAddr, name);
    } else faddr = ptr(liborAddr);
    
    if(!faddr) {
        console.log("[+] makefunction failed to find faddr for", name);
        return null;
    }
    
    for(let i in argList) {
        if(argList[i] == 'string') argType.push('pointer');
        else argType.push(argList[i]);
    }
    
    if(retType == 'string') nativef = new NativeFunction(faddr, 'pointer', argType, options);
    else nativef = new NativeFunction(faddr, retType, argType, options);
    
    return function() {
        let args = [];
        for(let i in arguments) {
            if(argList[i] == 'string' && typeof arguments[i] == 'string') {
                args.push(Memory.allocUtf8String(arguments[i]));
            }
            else args.push(arguments[i]);
        }
        let retVal = nativef(...args);
        if(retType == 'string') {
            retVal = retVal.readCString();
        }
        return retVal;
    }
}
exports.makefunction = makefunction;

const modulesApi = {};
function apiCaller() {
    if(this.nativeFunction) {
        return this.nativeFunction.apply(this.nativeFunction, arguments);
    }
    if(this.signature !== undefined) {
        this.nativeFunction = makefunction(
            this.ptr, '',
            this.signature.retType, 
            this.signature.argList, 
            this.signature.options);
        return this.nativeFunction.apply(this.nativeFunction, arguments);
    }
    console.log(`[E] signature for function ${this.name} hasn't defined.`);
    return null;
}
const modulesApiProxy = new Proxy(modulesApi, {
    has(target, property) {
        return findModuleByName(property) !== null;
    },
    get(target, property) {
        if(property in target) {
            return target[property];
        }
        const module = findModuleByName(property);
        if(module === null) return;
        
        const wrapper = {};
        wrapper.$module = module;
        module.enumerateExports().forEach(function (exp) {
            if(exp.name in wrapper) {
                // console.log(exp.type, exp.name, exp.address);
                return;
            }
            if(exp.type === 'function') {
                const functionWrapper = {};
                functionWrapper.ptr = exp.address;
                functionWrapper.name = exp.name;
                functionWrapper.wrapper = apiCaller.bind(functionWrapper);
                functionWrapper.wrapper.ptr = exp.address;
                Object.defineProperty(functionWrapper.wrapper, 'signature', {
                    get: function() {
                       return functionWrapper.signature;
                    },
                    set: function(signature) {
                        functionWrapper.signature = {
                            retType: signature[0],
                            argList: signature[1],
                            options: signature.length === 3 ? signature[2] : undefined
                        }
                    }
                });
                Object.defineProperty(wrapper, exp.name, {
                    get: function() {
                        return functionWrapper.wrapper;
                    },
                    set: function(signature) {
                        // TODO: replace / attach
                        functionWrapper.signature = {
                            retType: signature[0],
                            argList: signature[1],
                            options: signature.length === 3 ? signature[2] : undefined
                        }
                    }
                });
            }
            else if(exp.type === 'variable') {
                Object.defineProperty(wrapper, exp.name, {
                    get: function() {
                        return exp.address;
                    },
                    set: function(value) {
                        if(typeof(value) === 'number' || value instanceof NativePointer)
                            exp.address.writePointer(ptr(value));
                        else if(typeof(value) === 'string') {
                            const memstring = Memory.allocUtf8String(value);
                            exp.address.writePointer(memstring);
                        }
                        // databuffer / array
                    }
                });
            }
        });
        target[property] = wrapper;
        return wrapper;
    }
});
exports.modules = modulesApiProxy;

function findModuleByName(name) {
    let result = Process.findModuleByName(`lib${name}.so`);
    if(result === null) {
        result = Process.findModuleByName(`${name}.so`);
    }
    if(result === null) {
        result = Process.findModuleByName(`${name}`);
    }
    return result;
}

let customNames = [];
function setName( address, size, name ) {
    if(typeof(address) == 'object') address = parseInt(address.toString(), 16);
    customNames.push([address, size, name]);
}
exports.setName = setName;

function symbolName( address ) {
    let name = '';
    address = ptr(address);
    let addressvalue = parseInt(address.toString(), 16);
    for(let i in customNames) {
        let customName = customNames[i];
        let s_addr = customName[0];
        let size = customName[1];
        if(addressvalue >= s_addr && addressvalue < s_addr+size) {
            let offset = addressvalue-s_addr;
            name = customName[2];
            if(offset) name += "+"+ptr(offset);
            return name;
        }
    }
    let debugSymbol = DebugSymbol.fromAddress(address);
    let range       = Process.findRangeByAddress(address);
    if(debugSymbol && range)
        name = debugSymbol.toString()+' ('+range.base+'+'+address.sub(range.base)+')';
    else if(range) {
        name = '('+range.base+'+'+this.address.sub(range.base)+')';
        if(range.file)
            name = range.file.path + name;
    }else if(debugSymbol) {
        name = address + ' ' + debugSymbol.moduleName + '!' + debugSymbol.name;
    }
    else {
        name = address;
    }
    return name;
}
exports.symbolName = symbolName;

function getProtection( address ) {
    address = ptr(address);
    let range = Process.findRangeByAddress(address);
    let protection = null;
    if(range) {
        protection = range.protection;
    } else {
        log("[!] can't find range of address", address);
    }
    return protection;
}
exports.getProtection = getProtection;

function showAddrInfo( address ) {
    address = ptr(address);
    let debugSymbol = DebugSymbol.fromAddress(address);
    let module      = Process.findModuleByAddress(address);
    let range       = Process.findRangeByAddress(address);
    console.log("Addr", address, ":");
    console.log("\t" + JSON.stringify(debugSymbol));
    console.log("\t" + JSON.stringify(module));
    console.log("\t" + JSON.stringify(range));
}
exports.showAddrInfo = showAddrInfo;

function dumpMem ( address, size, fileName ) {
    address = ptr(address);
    let out = new File(fileName, "wb");
    let protection = getProtection(address);
    if(protection && protection[0] != 'r') {
        Memory.protect(address, size, 'r'+protection.slice(1));
    }
    out.write(Memory.readByteArray(address, size));
    out.close();
    if(protection && protection[0] != 'r') {
        Memory.protect(address, size, protection);
    }
}
exports.dumpMem = dumpMem;

function readNativeArg ( handle, name ) {
    let type = name[0];
    switch(type) {
        case 'p': //Pointer
            return handle;
        case 'i': //Int
            return handle.toInt32();
        case 's': //String
            return handle.readCString();
        case 'd': //Data
            if(!handle.isNull()) {
                if(parseInt(name.slice(1)))
                    return '\n' + hexdump(handle, {length:parseInt(name.slice(1))}) + '\n';
                else
                    return '\n' + hexdump(handle) + '\n';
            }else {
                return 'null';
            }
        case 'v': //Pointer => Value
            return handle + '=>' + handle.readPointer();
        case 'w': //Pointer => Value(Pointer) => Value
            return handle + '=>' + handle.readPointer()
                          + '=>' + handle.readPointer().readPointer();
        case 'r': //Register
            // TODO
        default:
            return handle+'(miss type)';
    }
}

function getArgName(name) {
    return name.substr(name.indexOf(".")+1);
}

function traceCalled ( liborAddr, funcName ) {
    let funcAddr;
    if(!liborAddr || typeof(liborAddr) == 'string') {
        funcAddr = Module.findExportByName(liborAddr, funcName);
        if(funcAddr == null) {
            console.log(`[E] couldn't find function ${funcName}'s address in lib ${liborAddr}`);
            return null;
        }
    } else {
        funcAddr = ptr(liborAddr);
    }
    let _hooks = {
        onEnter: function (args) {
            let tid = Process.getCurrentThreadId();
            console.log(`\n[${tid}]\t${funcName} called at ${symbolName(this.returnAddress)}`);
        },
        onLeave: function (retVal) {
            let tid = Process.getCurrentThreadId();
            console.log(`\n[${tid}]\t${funcName} returned ${retVal}`);
        }
    }
    return Interceptor.attach(funcAddr, _hooks);
}
exports.traceCalled = traceCalled;

function stopAt(addr, name) {
    addr = ptr(addr);
    Interceptor.attach(addr, {
        onEnter: function(args) {
            console.log("stopAt", addr, name);
            eval(easy_frida.interact);
        }
    });
}
exports.stopAt = stopAt;

// traceFunction(null, 'open', 'i.fd', ['s.name']);
// retType can be Array:
// traceFunction(null, 'memcpy', [
//      'p.dest',   // retval's type
//      'd32.dest', // arg1 as out
//                  // arg2 as out ...
//      ], 
//      ['p.dest', 'p.src', 'i.size']);
function traceFunction (liborAddr, funcName, retType, argList, hooks) {
    if(!hooks) hooks = {};
    let funcAddr;
    if(!liborAddr || typeof(liborAddr) == 'string') {
        funcAddr = Module.findExportByName(liborAddr, funcName);
        if(funcAddr == null) {
            console.log("[E] couldn't find function", funcName, "'s address in lib", liborAddr);
            return null;
        }
    } else {
        funcAddr = ptr(liborAddr);
    }
    let fid = 1;
    let _hooks = {
        onEnter: function (args) {
            this.tid = Process.getCurrentThreadId();
            this.args = [];
            this.fid = fid;
            fid += 1;
            let argslen = argList.length;
            if(retType instanceof Array && retType.length-1 > argslen)
                argslen = retType.length-1;
            for(let i = 0; i < argslen; ++i) {
                this.args.push(args[i]);
            }
            this.caller = symbolName(this.returnAddress);
            let logMsg = `[${this.tid}](${this.fid}): ${funcName}(`;
            let todump = [];
            if(argList.length > 0) {
                for(let i in argList) {
                    let argName = argList[i];
                    let argval = args[i];
                    if(argName[0] == 'd') {
                        logMsg += `${getArgName(argName)}=${argval}, `;
                        todump.push([argval, argName]);
                    } else {
                        logMsg += `${getArgName(argName)}=${readNativeArg(argval, argName)}, `;
                    }
                }
                logMsg = logMsg.slice(0, -2);
            }
            logMsg += `) \n\t\tCalled by ${this.caller}`;
            for(let i in todump) {
                logMsg += readNativeArg(todump[i][0], todump[i][1]);
            }
            console.log(logMsg);
            if(hooks && hooks.onEnter instanceof Function) {
                hooks.onEnter.apply(this, arguments);
            }
        },
        onLeave: function (retVal) {
            if(hooks && hooks.onLeave instanceof Function) {
                hooks.onLeave.apply(this, arguments);
            }
            let logMsg = '';
            if (retType instanceof Array) {
                logMsg += `[${this.tid}](${this.fid}): ${funcName} `;
                logMsg += `returned ${readNativeArg(retVal, retType[0])}.`;
                logMsg += '\nargs on return: \t';
                for(let i = 1; i < retType.length; ++i) {
                    logMsg += `${getArgName(retType[i])}: ${readNativeArg(this.args[i-1], retType[i])}, '`;
                }
                logMsg = logMsg.slice(0, -2);
            }
            else {
                logMsg += `[${this.tid}](${this.fid}): ${funcName} returned ${readNativeArg(retVal, retType)}.`;
            }
            logMsg += '\n';
            
            console.log(logMsg);
        }
    }
    let hd = Interceptor.attach(funcAddr, _hooks);
    Interceptor.flush();
    return hd;
}
exports.traceFunction = traceFunction;


// fn(0) called before lib's init functions called,
// fn(1) after.
let monitor_libs = [];
let linker = null;
function libraryOnLoad(libname, fn) {
    // __dl__ZN6soinfo17call_constructorsEv in /system/bin/linker | /system/bin/linker64
    const addr_arm = 0x1A63D;
    const addr_arm64 = 0x2FAC4;
    const addr_ia32 = 0x2DE8;
    
    monitor_libs.push([libname, fn]);
    let call_constructors;
    if(linker == null) {
        linker = Process.findModuleByName("linker");
        if(Process.arch == "arm") {
            call_constructors = linker.base.add(addr_arm); 
        } else if (Process.arch == "arm64") {
            call_constructors = linker.base.add(addr_arm64); 
        } else if (Process.arch == "ia32") {
            call_constructors = linker.base.add(addr_ia32); 
        } else if (Process.arch == "x64") {
            console.log("libraryOnLoad: TODO on x64's linker");
            return;
        }
        Interceptor.attach(call_constructors, {
            onEnter: function(args) {
                let soinfo;
                if(Process.arch == "ia32")
                    soinfo = ptr(this.context.eax);
                else
                    soinfo = args[0];
                let libname = soinfo.readCString();  
                this.libfn = null;
                for(let i in monitor_libs) {
                    let tohook = monitor_libs[i][0];
                    let libfn = monitor_libs[i][1];
                    if(libname.indexOf(tohook) >= 0) {
                        let tid = Process.getCurrentThreadId();
                        // console.log(`[${tid}] ${libname}'s initproc catched.`);
                        this.libfn = libfn;
                        libfn(0);
                    }
                }
            },
            onLeave: function(ret) {
                if(this.libfn) this.libfn(1);
            }
        });
        Interceptor.flush();
    }
}
exports.libraryOnLoad = libraryOnLoad;

function showThreads() {
    let threads = Process.enumerateThreads();
    for(let idx in threads) {
        let t = threads[idx];
        switch(Process.arch) {
            case 'arm':
                console.log(`[${t.id}:${t.state}] pc:${symbolName(t.context.pc)}, lr:${symbolName(t.context.lr)}`);
                break;
            case 'ia32':
                console.log(`[${t.id}:${t.state}] pc:${symbolName(t.context.pc)}`);
                break;
        }
    }
}
exports.showThreads = showThreads;

function findElfSegment(moduleOrName, segName) {
    let module = moduleOrName;
    if(typeof(moduleOrName) === 'string') {
        module = Process.findModuleByName(moduleOrName);
    }
    if(module) {
        let SHT_offset;
        let SHT_size_offset;
        let SHT_count_offset;
        let SHT_strtidx_offset;
        let SHTH_addr_offset;
        let SHTH_vaddr_offset;
        let SHTH_nameidx_offset = 0;
        let SHTH_size_offset;
        if(Process.arch === "arm" || Process.arch === "ia32" ) {
            SHT_offset = 0x20;
            SHT_size_offset = 0x2e;
            SHT_count_offset = 0x30;
            SHT_strtidx_offset = 0x32;
            
            SHTH_vaddr_offset = 0x0c;
            SHTH_addr_offset = 0x10;
            SHTH_size_offset = 0x14;
        } else if (Process.arch === "arm64" || Process.arch === "x64") {
            SHT_offset = 0x28;
            SHT_size_offset = 0x3a;
            SHT_count_offset = 0x3c;
            SHT_strtidx_offset = 0x3e;
            
            SHTH_vaddr_offset = 0x10;
            SHTH_addr_offset = 0x18;
            SHTH_size_offset = 0x20;
        }
        // const elf = new File(module.path, 'rb');
        modulesApiProxy.c.fopen = ['pointer', ['string', 'string']];
        modulesApiProxy.c.fseek = ['int', ['pointer', 'int', 'int']];
        modulesApiProxy.c.ftell = ['int', ['pointer']];
        modulesApiProxy.c.fread = ['uint', ['pointer', 'uint', 'uint', 'pointer']];
        modulesApiProxy.c.malloc = ['pointer', ['uint']];
        modulesApiProxy.c.free = ['int', ['pointer']];
        modulesApiProxy.c.fclose = ['int', ['pointer']];
        
        const fd = modulesApiProxy.c.fopen(module.path, 'rb');
        modulesApiProxy.c.fseek(fd, 0, 2);
        const fsize = modulesApiProxy.c.ftell(fd);
        const buffer = modulesApiProxy.c.malloc(fsize + 0x10);
        modulesApiProxy.c.fseek(fd, 0, 0);
        modulesApiProxy.c.fread(buffer, fsize, 1, fd);
        modulesApiProxy.c.fclose(fd);
        
        const SHT = buffer.add(SHT_offset).readPointer();
        const SHT_size = buffer.add(SHT_size_offset).readU16();
        const SHT_count = buffer.add(SHT_count_offset).readU16();
        const SHT_strtidx = buffer.add(SHT_strtidx_offset).readU16();
        const SHT_strtblItem = buffer.add(SHT).add(SHT_strtidx*SHT_size);
        const segNameTable = buffer.add(SHT_strtblItem.add(SHTH_addr_offset).readPointer());
        for(let i = 0; i < SHT_count; ++i) {
            let SHT_item = buffer.add(SHT).add(i*SHT_size);
            let curSegAddr = SHT_item.add(SHTH_vaddr_offset).readPointer();
            let curSegSize = parseInt(SHT_item.add(SHTH_size_offset).readPointer().toString(10));
            let segNamePtr = segNameTable.add(SHT_item.add(SHTH_nameidx_offset).readU16());
            let curSegName = segNamePtr.readCString();
            if(curSegName === segName) {
                modulesApiProxy.c.free(buffer);
                return {addr: module.base.add(curSegAddr), size: curSegSize};
            }
        }
        modulesApiProxy.c.free(buffer);
        return null;
    }
}
exports.findElfSegment = findElfSegment;

// for case gadget is globally injected,
// sometimes it will suspend when use server at same time.
function avoidConflict() {
    function diableGadgets() {
        const fridaGadget = Process.findModuleByName("libadirf.so");
        const initseg = findElfSegment(fridaGadget, ".init_array");
        Memory.protect(initseg.addr, initseg.size, 'rw-');
        for(let offset = 0; offset < initseg.size; offset += Process.pointerSize) {
            let fptr = initseg.addr.add(offset).readPointer();
            if(fptr.isNull()) break;
            initseg.addr.add(offset).writePointer(easy_frida.nullcb);
        }
    }
    if(easy_frida.isServer) {
        libraryOnLoad("libqti_performance.so", diableGadgets);
    }
}
exports.avoidConflict = avoidConflict;