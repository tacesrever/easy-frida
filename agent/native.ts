import { interact } from ".";

export function showBacktrace(context?: CpuContext) {
    let bt = Thread.backtrace(context, Backtracer.ACCURATE).map(symbolName).join("\n\t");
    console.log('\t' + bt);
}
/**
 * similar to hexdump,  
 * for lazy people who don't want to write "console.log(hexdump(...))" when debuging.
 */
export function d(address: number | NativePointer, size?: number) {
    let p: NativePointer;
    if(address instanceof NativePointer) {
        p = address;
    } else {
        p = ptr(address);
    }
    if(size) {
        console.log(hexdump(p, {length:size}));
    } else {
        console.log(hexdump(p));
    }
}
/**
 * warpper for NativeFunction, add 'string' type.
 * slower, just for convenience.
 */
type NativeFunctionReturnTypeMapEx = NativeFunctionReturnTypeMap & {
    string: string;
}
type NativeFunctionReturnTypeEx = RecursiveKeysOf<NativeFunctionReturnTypeMapEx>;
type NativeFunctionReturnValueEx = RecursiveValuesOf<NativeFunctionReturnTypeMapEx>;

type GetNativeFunctionReturnValueEx<T extends NativeFunctionReturnTypeEx> = GetValue<
    NativeFunctionReturnTypeMapEx,
    NativeFunctionReturnValueEx,
    NativeFunctionReturnTypeEx,
    T
>;

type NativeFunctionArgumentTypeMapEx = NativeFunctionArgumentTypeMap & {
    string: string;
}
type NativeFunctionArgumentTypeEx = RecursiveKeysOf<NativeFunctionArgumentTypeMapEx>;
type NativeFunctionArgumentValueEx = RecursiveValuesOf<NativeFunctionArgumentTypeMapEx>;

type GetNativeFunctionArgumentValueEx<T extends NativeFunctionArgumentTypeEx> = GetValue<
    NativeFunctionArgumentTypeMapEx,
    NativeFunctionArgumentValueEx,
    NativeFunctionArgumentTypeEx,
    T
>;

export interface NativeFunctionEx<RetType extends NativeFunctionReturnValueEx, ArgTypes extends NativeFunctionArgumentValueEx[] | []>
    extends NativePointer {
    (...args: ArgTypes): RetType;
    apply(thisArg: NativePointerValue | null | undefined, args: ArgTypes): RetType;
    call(thisArg?: NativePointerValue | null, ...args: ArgTypes): RetType;
}

export function importfunc <RetType extends NativeFunctionReturnTypeEx, ArgTypes extends NativeFunctionArgumentTypeEx[] | []> (
        libnameOrFuncaddr: string | NativePointerValue | null,
        funcName: string,
        retType: RetType,
        argTypes: ArgTypes,
        abiOrOptions?: NativeABI | NativeFunctionOptions) {
    let funcAddress: NativePointerValue;
    
    if(!libnameOrFuncaddr) {
        funcAddress = Module.getGlobalExportByName(funcName);
    } else if(typeof(libnameOrFuncaddr) == 'string') {
        funcAddress = Process.getModuleByName(libnameOrFuncaddr).getExportByName(funcName);
    } else {
        funcAddress = libnameOrFuncaddr;
    }
    
    const realRetType = retType === 'string' ? 'pointer' : retType;
    const realArgTypes = argTypes.map(argType => argType === 'string' ? 'pointer' : argType);

    let nativeFunction = new (<any>NativeFunction)(funcAddress, realRetType, realArgTypes, abiOrOptions);

    return new Proxy(nativeFunction, {
        apply: (target, thisArg, args) => {
            let nativeArgs: NativeFunctionArgumentValue[] = [];
            for(const arg of args) {
                if(typeof arg === 'string') {
                    nativeArgs.push(Memory.allocUtf8String(arg));
                }
                else nativeArgs.push(arg);
            }
            try {
                let retVal = target(...nativeArgs);
                if(retType === 'string') {
                    return (retVal as NativePointer).readCString();
                }
                return retVal;
            } catch(e) {
                console.log("error calling", funcName);
                throw e;
            }
        }
    }) as NativeFunctionEx<GetNativeFunctionReturnValueEx<RetType>,ResolveVariadic<Extract<GetNativeFunctionArgumentValueEx<ArgTypes>, unknown[]>>>;
}

let customNames: {
    address: number,
    size: number,
    name: string
}[] = [];
/**
 * set custom debug symbol name to range.
 * show as name or name+offset.
 */
export function setName(address: number | NativePointer, size: number, name: string) {    
    if(address instanceof NativePointer) address = parseInt(address.toString());
    customNames.push({address, size, name});
}

export function symbolName(address: number | NativePointer) {
    let name: string;
    if(typeof address === 'number') address = ptr(address);
    const addressvalue = parseInt(address.toString());
    for(const customName of customNames) {
        const s_addr = customName.address;
        const size = customName.size;
        if(addressvalue >= s_addr && addressvalue < s_addr+size) {
            const offset = addressvalue-s_addr;
            name = customName.name;
            if(offset) name += "+"+ptr(offset);
            return name;
        }
    }

    const module = Process.findModuleByAddress(address);
    const range = Process.findRangeByAddress(address);
    const debugSymbol = DebugSymbol.fromAddress(address);
    
    if(debugSymbol && range) {
        name = debugSymbol.moduleName + '!' + debugSymbol.name+' ('+range.base+'+'+address.sub(range.base)+')';
    } else if(range) {
        name = '('+range.base+'+'+address.sub(range.base)+')';
        if(range.file)
            name = range.file.path + name;
        else if(module)
            name = module.name + name;
    } else if(debugSymbol) {
        name = address + ' ' + debugSymbol.moduleName;
        if(debugSymbol.name !== null) {
            let symbolBase = DebugSymbol.fromName(debugSymbol.name);
            let offset = address.sub(symbolBase.address);
            name += '!' + debugSymbol.name + '+' + offset;
        }
        if(debugSymbol.fileName !== null) {
            const basepos = debugSymbol.fileName.lastIndexOf('/');
            name += '(' + debugSymbol.fileName.slice(basepos + 1) + ':' + debugSymbol.lineNumber + ')';
        }
    }
    else {
        name = address.toString();
    }
    return name;
}
/**
 * show addrinfo from DebugSymbol.fromAddress, findModuleByAddress and findRangeByAddress.
 */
export function showAddrInfo(address: number | NativePointer) {
    if(typeof address === 'number') address = ptr(address);
    const debugSymbol = DebugSymbol.fromAddress(address);
    const module = Process.findModuleByAddress(address);
    const range = Process.findRangeByAddress(address);
    console.log("AddrInfo of", address, ":");
    console.log("\t" + JSON.stringify(debugSymbol));
    console.log("\t" + JSON.stringify(module));
    console.log("\t" + JSON.stringify(range));
};
/**
 * dump memory to file.
 */
export function dumpMem(address: number | NativePointer, size:number, outname: string) {
    if(typeof address === 'number') address = ptr(address);
    const out = new File(outname, "wb");
    const protection = Process.findRangeByAddress(address).protection;

    if(protection && protection[0] != 'r') {
        Memory.protect(address, size, 'r'+protection.slice(1));
    }
    const data = address.readByteArray(size) || "";
    out.write(data);
    out.close();
    if(protection && protection[0] != 'r') {
        Memory.protect(address, size, protection);
    }
};

function readNativeArg (handle: NativePointer, name: string) {
    let type = name[0];
    switch(type) {
        case 'p': //Pointer
            return handle;
        case 'i': //Int
            return handle.toInt32();
        case 's': //String
            return handle.readCString();
        case 'u':
            return handle.readUtf16String();
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

function getArgName(name: string) {
    return name.substring(name.indexOf(".")+1);
}

export function traceCalled(libnameOrFuncaddr: string | NativePointerValue | null, funcName: string) {
    let funcAddr: NativePointerValue;
    if(!libnameOrFuncaddr) {
        funcAddr = Module.getGlobalExportByName(funcName);
    } else if(typeof(libnameOrFuncaddr) == 'string') {
        funcAddr = Process.getModuleByName(libnameOrFuncaddr).getExportByName(funcName);
    } else {
        funcAddr = libnameOrFuncaddr;
    }
    let _hooks: InvocationListenerCallbacks = {
        onEnter: function (args) {
            let tid = Process.getCurrentThreadId();
            console.log(`\n[${tid}]\t${funcName} called at ${symbolName(this.returnAddress)}`);
        },
        onLeave: function (retVal) {
            let tid = Process.getCurrentThreadId();
            console.log(`\n[${tid}]\t${funcName} return ${retVal}`);
        }
    }
    return Interceptor.attach(funcAddr, _hooks);
}
/**
 * typeformat: T.name, where T is:  
 * p: Pointer  
 * i: int  
 * s: String  
 * d%d|%x: data and it's length  
 * v: Pointer => Value  
 * w: Pointer => Pointer => Value  
 * example: traceFunction(null, 'open', 'i.fd', ['s.name', 'p.flag'])  
 */
export function traceFunction(
        libnameOrFuncaddr: string | NativePointerValue | null,
        funcName: string,
        retType: string | string[],
        argTypes: string[],
        hooks: ScriptInvocationListenerCallbacks = {}) {
    let funcAddr: NativePointerValue;
    if(!libnameOrFuncaddr) {
        funcAddr = Module.getGlobalExportByName(funcName);
    } else if(typeof(libnameOrFuncaddr) == 'string') {
        funcAddr = Process.getModuleByName(libnameOrFuncaddr).getExportByName(funcName);
    } else {
        funcAddr = libnameOrFuncaddr;
    }
    let fid = 1;
    let _hooks: InvocationListenerCallbacks = {
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
            const todump: {
                handle: NativePointer,
                name: string
            }[] = [];
            if(argTypes.length > 0) {
                for(let i in argTypes) {
                    let name = argTypes[i];
                    let handle = args[i];
                    if(name[0] == 'd') {
                        logMsg += `${getArgName(name)}=${handle}, `;
                        todump.push({handle, name});
                    } else {
                        logMsg += `${getArgName(name)}=${readNativeArg(handle, name)}, `;
                    }
                }
                logMsg = logMsg.slice(0, -2);
            }
            logMsg += `) \n\t\tCalled by ${this.caller}`;
            for(let i in todump) {
                logMsg += readNativeArg(todump[i].handle, todump[i].name);
            }
            console.log(logMsg);
            if(hooks && hooks.onEnter instanceof Function) {
                hooks.onEnter.call(this, args);
            }
        },
        onLeave: function (retVal) {
            if(hooks && hooks.onLeave instanceof Function) {
                hooks.onLeave.call(this, retVal);
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
    return Interceptor.attach(funcAddr, _hooks);
};
/**
 * https://codeshare.frida.re/@oleavr/read-std-string/
 */
export function readStdString(strHandle: NativePointer) {
    const isTiny = (strHandle.readU8() & 1) === 0;
    if (isTiny) {
        return strHandle.add(1).readUtf8String();
    }
    return strHandle.add(2 * Process.pointerSize).readPointer().readUtf8String();
};

export function cprintf(format: string, args: NativePointer[], vaArgIndex = 1, maxSize = 0x1000) {
    let count = 0;
    for(let i = 0; i < format.length - 1; ++i) {
        if(format[i] === '%') {
            i++;
            if(format[i] !== '%') count++;
        }
    }
    const buffer = Memory.alloc(maxSize);
    const types: NativeFunctionArgumentTypeEx[] = ['pointer', 'pointer', 'string'];
    const snprintfArgs = [ buffer, ptr(maxSize), format ];
    for(let i = 0; i < count; ++i) {
        types.push('pointer');
        snprintfArgs.push(args[vaArgIndex + i]);
    }
    const snprintf = importfunc(null, 'snprintf', 'int', types);
    (snprintf as any)(...snprintfArgs);
    return buffer.readUtf8String();
};

export function showThreads() {
    const pthread_getname_np = importfunc(null, "pthread_getname_np", 'int', ['pointer', 'pointer']);
    let threads = Process.enumerateThreads();
    let buf = Memory.alloc(0x100);
    for(let idx in threads) {
        let t = threads[idx];
        try {
            let ret = pthread_getname_np(ptr(t.id), buf);
            if(ret === 0) {
                console.log(`[${t.id}-${buf.readCString()}:${t.state}] pc:${symbolName(t.context.pc)}`);
                continue;
            }
        } catch(e) {}
        console.log(`[${t.id}:${t.state}] pc:${symbolName(t.context.pc)}`);
    }
}

export function showThread(tid: number) {
    const pthread_getname_np = importfunc(null, "pthread_getname_np", 'int', ['pointer', 'pointer']);
    let thread = Process.enumerateThreads().filter(t => t.id === tid)[0];
    if(thread) {
        let buf = Memory.alloc(0x100);
        let threadName = tid.toString();
        let ret = pthread_getname_np(ptr(thread.id), buf);
        if(ret === 0) threadName = buf.readCString();
        console.log("thread name:", threadName);
        showCpuContext(thread.context);
        console.log("backtrace:");
        showBacktrace(thread.context);
    }
}

export function showCpuContext(context: CpuContext) {
    let i = 0, regsinfo = "";
    for(const regname of Object.getOwnPropertyNames((<any>context).__proto__)) {
        if(regname === "toJSON") continue;
        const module = Process.findModuleByAddress(context[regname]);
        const range = Process.findRangeByAddress(context[regname]);
        
        let regnum = parseInt(context[regname]).toString(16);
        let padn = Process.pointerSize*2 - regnum.length;
        if(padn > 0) regnum = (new Array(padn + 1)).join('0') + regnum;
        
        if((range && !range.base.isNull()) || module) {
            if(i%4 !== 1) regsinfo += "\n";
            let symname = symbolName(context[regname]);
            regsinfo += regname + "=" + regnum + " " + symname;
            i = 0;
        } else {
            regsinfo += regname + "=" + regnum + "\t";
        }
        if(i%4 === 0) regsinfo += "\n";
        i++;
    }
    console.log(regsinfo);
    try {
        const inst = Instruction.parse(context.pc);
        console.log("At", symbolName(context.pc), inst.mnemonic, inst.opStr);
    } catch {
        console.log("At", symbolName(context.pc), "??");
    }
}

export function showDiasm(pc: NativePointer) {
    let inst;
    for(inst = Instruction.parse(pc); !inst.groups.includes('jump') && !inst.groups.includes('ret'); inst = Instruction.parse(inst.next)) {
        console.log(inst.address, inst.mnemonic, inst.opStr);
    }
    console.log(inst.address, inst.mnemonic, inst.opStr);
}

//shouldShow: (context: CpuContext) => boolean, shouldBreak: (context: CpuContext) => boolean, shouldStop: (context: CpuContext) => boolean
export function traceExecBlockByStalkerAt(addr: NativePointer, onExecBlock: (ctx: CpuContext, block: any[]) => void) {
    const compiledBlocks: {
        [index: string]: string[]
    } = {};

    const once = Interceptor.attach(addr, function() {
        once.detach();
        (Interceptor as any).flush();
        let preTrace = true;
        const tid = Process.getCurrentThreadId();
        const targetBase = Process.findRangeByAddress(addr).base;
        Stalker.follow(tid, {
            transform: function(iterator) {
                const startInst = iterator.next();
                let inst = startInst;
                if(preTrace) {
                    const range = Process.findRangeByAddress(inst.address);
                    if(range && targetBase.equals(range.base)) preTrace = false;
                    else {
                        while(inst !== null) {
                            iterator.keep();
                            inst = iterator.next();
                        }
                        return;
                    }
                }
                const blockId = startInst.address.toString();
                compiledBlocks[blockId] = [];
                iterator.putCallout(handleBlock);
                if(startInst != null) showDiasm(startInst.address);
                while(inst !== null) {
                    const tinst = inst;
                    compiledBlocks[blockId].push(tinst.toString());
                    iterator.keep();
                    inst = iterator.next();
                }
            }
        });

        function handleBlock(context) {
            const blockId = context.pc.toString();
            onExecBlock(context, compiledBlocks[blockId]);
        //     if(shouldShow(context)) {
        //         showCpuContext(context);
        //         const blockId = context.pc.toString();
        //         console.log(compiledBlocks[blockId].join('\n'));
        //     }
        //     if(shouldBreak(context)) eval(interact);
        //     if(shouldStop(context)) {
        //         Stalker.unfollow(tid);
        //     }
        }
    });
}

export function showNativeExecption(handler?: ExceptionHandlerCallback) {
    Process.setExceptionHandler(function(details) {
        if(details.memory) {
            console.log(details.type, details.memory.operation, details.memory.address, "at", details.address);
        }
        else {
            console.log(details.type, "at", details.address);
        }
        showCpuContext(details.context);
        if(handler) return handler(details);
    });
}

export function setThreadStackRangeNames() {
    Process.enumerateThreads().forEach(function(thread) {
        const stackRange = Process.findRangeByAddress(thread.context.sp);
        setName(stackRange.base, stackRange.size, "tid-" + thread.id + "-stack");
    });
}