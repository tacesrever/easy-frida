'use strict';
const easy_frida = require("./easy_frida");

function backtrace( context ) {
    let bt = Thread.backtrace(context, Backtracer.ACCURATE).map(symbolName).join("\n\t");
    console.log('\t' + bt);
}
exports.backtrace = backtrace;

function d(addr, n) {
    if(n) {
        console.log(hexdump(ptr(addr), {length:n}));
    } else {
        console.log(hexdump(ptr(addr)));
    }
}
exports.d = d;

function makefunction(libnameOrAddr, name, retType, argTypes, abiOrOptions) {
    let funcAddress, realArgTypes = [], nativeFunction;
      
    if (libnameOrAddr === null || typeof libnameOrAddr === 'string') {
        funcAddress = Module.findExportByName(libnameOrAddr, name);
        if(funcAddress === null) {
            console.log("[E] makefunction failed to find faddr for", name);
            return null;
        }
    } else funcAddress = libnameOrAddr;
    
    argTypes.forEach(type => {
        if(type === 'string') realArgTypes.push('pointer');
        else realArgTypes.push(type);
    });
    
    if(retType === 'string') nativeFunction = new NativeFunction(funcAddress, 'pointer', realArgTypes, abiOrOptions);
    else nativeFunction = new NativeFunction(funcAddress, retType, realArgTypes, abiOrOptions);

    return function() {
        let args = [];
        for(let i in arguments) {
            if(argTypes[i] === 'string' && typeof arguments[i] === 'string') {
                args.push(Memory.allocUtf8String(arguments[i]));
            } else args.push(arguments[i]);
        }
        let retVal = nativeFunction(...args);
        if(retType === 'string') {
            retVal = retVal.readCString();
        }
        return retVal;
    }
}
exports.makefunction = makefunction;

let customNames = [];
function setName( address, size, name ) {
    if(typeof(address) === 'object') address = parseInt(address.toString(), 16);
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

function dumpMem(address, size, fileName) {
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
        module.enumerateExports().forEach(exp =>  {
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
                    set: function(value) {
                        if(value instanceof Array) {
                            functionWrapper.signature = {
                                retType: value[0],
                                argList: value[1],
                                options: value.length === 3 ? value[2] : undefined
                            }
                        }
                        else if(value instanceof Function) {
                            if(functionWrapper.signature !== undefined) {
                                const callback = new NativeCallback(value, functionWrapper.signature.retType, functionWrapper.signature.argList);
                                Interceptor.replace(functionWrapper.ptr, callback);
                            }
                            else
                                console.log(`[E] signature for function ${functionWrapper.name} hasn't defined.`);
                        }
                        else if(value.onEnter !== undefined || value.onLeave !== undefined) {
                            Interceptor.attach(functionWrapper.ptr, value);
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
    let result = Process.findModuleByName(name);
    if(result !== null) return result;
    switch(Process.platform) {
        case 'windows':
            name += '.dll';
            break;
        case 'linux':
        case 'qnx':
            name += '.so';
            break;
        case 'darwin':
            name += '.dylib';
            break;
    }
    result = Process.findModuleByName(name);
    if(result !== null) return result;
    result = Process.findModuleByName('lib' + name);
    return result;
}

function readStdString(str) {
    const isTiny = (str.readU8() & 1) === 0;
    if (isTiny) {
    return str.add(1).readUtf8String();
    }
    return str.add(2 * Process.pointerSize).readPointer().readUtf8String();
}
exports.readStdString = readStdString;

function cprintf(format, args, vaArgIndex = 1) {
    let handleidx = vaArgIndex;
    let result = '';
    let numbers = "0123456789";
    let flagschar = "-+ 0'#";
    // %[parameter][flags][width][.precision][length]type
    let transer = Memory.alloc(16);
    for(let i = 0; i < format.length; ++i) {
        if(format[i] == '%') {
            i++;
            // parameter
            if(numbers.indexOf(format[i]) >= 0) {
                let j = 1;
                while(numbers.indexOf(format[i + j]) >= 0) ++j;
                if(format[i + j] == '$') {
                    // parameter selector here
                    handleidx = parseInt(format.slice(i, j));
                    i = i + j + 1;
                }
            }
            // flags
            let positiveSign = '';
            let numpad = ' ';
            while(flagschar.indexOf(format[i]) >= 0) {
                switch(format[i]) {
                    case "-":
                        // TODO: Left-align
                        break;
                    case "+":
                        positiveSign = '+';
                        break;
                    case " ":
                        if(positiveSign == '') positiveSign = ' ';
                        break;
                    case "0":
                        numpad = '0';
                        break;
                    case "'":
                        // TODO: thousands grouping separator
                        break;
                    case "#":
                        // TODO 
                        break;
                }
                ++i;
            }
            // width
            let minOutChars = null;
            if(numbers.indexOf(format[i]) >= 0) {
                let j = 1;
                while(numbers.indexOf(format[i + j]) >= 0) ++j;
                minOutChars = parseInt(format.slice(i, j));
                i = i + j;
            }
            else if(format[i] == "*") {
                minOutChars = args[handleidx].toUInt32();
                handleidx++;
                i++;
            }
            // .precision
            let maxOutChars = null;
            if(format[i] == ".") {
                i++;
                if(numbers.indexOf(format[i]) >= 0) {
                    let j = 1;
                    while(numbers.indexOf(format[i + j]) >= 0) ++j;
                    maxOutChars = parseInt(format.slice(i, j));
                    i = i + j;
                }
                else if(format[i] == "*") {
                    maxOutChars = args[handleidx].toUInt32();
                    handleidx++;
                    i++;
                }
            }
            // Length
            let length = null;
            switch(format[i]) {
                case 'h':
                    if(format[i+1] == 'h') {
                        i++;
                        length = 1;
                    }
                    else length = 2;
                    i++;
                    break;
                case 'l':
                    if(format[i+1] == 'l') {
                        length = 8;
                        i++;
                    }
                    else length = 4;
                    i++;
                    break;
                case 'L':
                    // TODO
                    i++;
                    break;
                case 'z':
                    length = Process.pointerSize;
                    i++;
                    break;
                case 'j':
                    length = 4;
                    i++;
                    break;
                case 't':
                    length = Process.pointerSize;
                    i++;
                    break;
            }
            // type
            // TODO: witdh and length control
            switch(format[i]) {
                case "%":
                    result += "%";
                    break;
                case "d":
                case "i":
                    // TODO: 64bit minus
                    if(length && length >= 8) result += parseInt(args[handleidx]);
                    else result += args[handleidx].toInt32();
                    handleidx++;
                    break;
                case "u":
                    if(length && length >= 8) result += parseInt(args[handleidx]);
                    result += args[handleidx].toUInt32();
                    handleidx++;
                    break;
                case "f":
                case "F":
                    transer.writePointer(args[handleidx]);
                    result += transer.readDouble();
                    handleidx++;
                    break;
                case "e":
                case "E":
                case "g":
                case "G":
                    // TODO
                    transer.writePointer(args[handleidx]);
                    result += transer.readDouble();
                    handleidx++;
                    break;
                case "x":
                    if(length && length >= 8) result += parseInt(args[handleidx]).toString(16);
                    else result += args[handleidx].toUInt32().toString(16);
                    handleidx++;
                    break;
                case "X":
                    if(length && length >= 8) result += parseInt(args[handleidx]).toString(16).toUpperCase();
                    else result += args[handleidx].toUInt32().toString(16).toUpperCase();
                    handleidx++;
                    break;
                case "o":
                    if(length && length >= 8) result += parseInt(args[handleidx]).toString(8);
                    else result += args[handleidx].toUInt32().toString(8);
                    handleidx++;
                    break;
                case "s":
                    result += args[handleidx].readCString();
                    handleidx++;
                    break;
                case "c":
                    result += String.fromCharCode(args[handleidx].toUInt32() & 0xff);
                    handleidx++;
                    break;
                case "p":
                    result += args[handleidx];
                    handleidx++;
                    break;
                case "a":
                case "A":
                    result += args[handleidx];
                    handleidx++;
                    break;
                case "n":
                    // do nothing here
                    handleidx++;
                    break;
            }
        }
        else {
            result += format[i];
        }
    }
    return result;
}
exports.cprintf = cprintf;

function traceFunction (liborAddr, funcName, retType, argTypes, hooks) {
    if(hooks === undefined) hooks = {};
    let funcAddr;
    if(liborAddr === null || typeof(liborAddr) == 'string') {
        funcAddr = Module.findExportByName(liborAddr, funcName);
        if(funcAddr === null) {
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
            let argslen = argTypes.length;
            if(retType instanceof Array && retType.length-1 > argslen)
                argslen = retType.length-1;
            for(let i = 0; i < argslen; ++i) {
                this.args.push(args[i]);
            }
            this.caller = symbolName(this.returnAddress);
            let logMsg = `[${this.tid}](${this.fid}): ${funcName}(`;
            let todump = [];
            if(argTypes.length > 0) {
                for(let i in argTypes) {
                    let argName = argTypes[i];
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

function showThreads() {
    let threads = Process.enumerateThreads();
    for(let idx in threads) {
        let t = threads[idx];
        switch(Process.arch) {
            case 'arm':
            case 'arm64':
                console.log(`[${t.id}:${t.state}] pc:${symbolName(t.context.pc)}, lr:${symbolName(t.context.lr)}`);
                break;
            case 'ia32':
                console.log(`[${t.id}:${t.state}] pc:${symbolName(t.context.pc)}`);
                break;
        }
    }
}
exports.showThreads = showThreads;