
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
        // console.log("[+] makefunction failed to find faddr for", name);
        return null;
    }
    
    for(let i in argList) {
        if(argList[i] == 'string') argType.push('pointer');
        else argType.push(argList[i]);
    }
    
    if(retType == 'string') nativef = new NativeFunction(faddr, 'pointer', argType, options);
    else nativef = new NativeFunction(faddr, retType, argType, options);
    
    return () => {
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
    // firstly use some reverse tool to find call_constructors's address in /system/bin/linker.
    // only tested on android.
    const addr_arm = 0x1A63D;
    const addr_ia32 = 0x2DE8;
    
    monitor_libs.push([libname, fn]);
    let call_constructors;
    if(linker == null) {
        linker = Process.findModuleByName("linker");
        if(Process.arch == "arm") {
            call_constructors = linker.base.add(addr_arm); 
        } else if (Process.arch == "arm64") {
            console.log("libraryOnLoad: TODO on arm64's linker");
            return;
        } else if (Process.arch == "ia32") {
            call_constructors = linker.base.add(addr_ia32); 
        } else if (Process.arch == "x64") {
            console.log("libraryOnLoad: TODO on x64's linker");
            return;
        } else {
            console.log("libraryOnLoad: arch error");
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
                        console.log(`[${tid}] ${libname}'s initproc catched.`);
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


let _dlopen = makefunction(null, 'dlopen', 'pointer', ['string', 'int']);
let dlclose = makefunction(null, 'dlclose', 'pointer', ['pointer']);
exports.dlclose = dlclose;
let dlerror = makefunction(null, 'dlerror', 'string', []);
function dlopen(dlname) {
    const RTLD_LOCAL=0, RTLD_LAZY=1, RTLD_NOW=2, RTLD_NOLOAD=4, RTLD_DEEPBIND=8;
    const RTLD_GLOBAL=0x100, RTLD_NODELETE=0x1000;
    if(!_dlopen) return null;
    var ret = _dlopen(dlname, RTLD_NOW);
    if(ret.isNull()) console.log(dlerror());
    else console.log("[+] loaded:", dlname);
    return ret;
}
exports.dlopen = dlopen;

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

// for case gadget is globally injected,
// sometimes it will suspend when use server at same time.
function avoidConflict() {
    function diableGadgets() {
        if(Process.arch == "arm") {
            // frida-gadget-12.8.0-android-arm.so
            var m = Process.findModuleByName("libadirf.so");
            // clean .init_array
            // TODO: can be done by dyn find .init_array from elf header.
            Memory.protect(m.base.add(0xDC0F04), 28,'rw-');
            m.base.add(0xDC0F04).writePointer(easy_frida.nullcb);
            m.base.add(0xDC0F08).writePointer(easy_frida.nullcb);
            m.base.add(0xDC0F0C).writePointer(easy_frida.nullcb);
            m.base.add(0xDC0F10).writePointer(easy_frida.nullcb);
            m.base.add(0xDC0F14).writePointer(easy_frida.nullcb);
            m.base.add(0xDC0F18).writePointer(easy_frida.nullcb);
            m.base.add(0xDC0F1C).writePointer(easy_frida.nullcb);
        } else if (Process.arch == "arm64") {
            // frida-gadget-12.8.0-android-arm64.so
            var m = Process.findModuleByName("libadirf.so");
            // clean .init_array
            Memory.protect(m.base.add(0x1277E80), 28,'rw-');
            m.base.add(0x1277E80).writePointer(easy_frida.nullcb);
            m.base.add(0x1277E84).writePointer(easy_frida.nullcb);
            m.base.add(0x1277E88).writePointer(easy_frida.nullcb);
            m.base.add(0x1277E8C).writePointer(easy_frida.nullcb);
            m.base.add(0x1277E90).writePointer(easy_frida.nullcb);
            m.base.add(0x1277E84).writePointer(easy_frida.nullcb);
            m.base.add(0x1277E88).writePointer(easy_frida.nullcb);
        }
    }
    // lib which injected by lief's add_library or etc.
    libraryOnLoad("libqti_performance.so", diableGadgets);
}
exports.avoidConflict = avoidConflict;