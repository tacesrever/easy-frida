
import * as easy_frida from './easy_frida';
import { cprintf, makefunction, readStdString } from './native';
import { findElfSegment } from './linux';

export function showJavaBacktrace() {
    console.log(javaBacktrace());
}
export function javaBacktrace(): string {
    const androidUtilLog = Java.use('android.util.Log');
    const exception = Java.use('java.lang.Exception').$new();
    return androidUtilLog.getStackTraceString(exception);
}
/**
 * show android log at console.
 */
export function showLogcat(level: number = 255) {
    const levelstrs = ['F', 'E', 'W', 'I', 'D', 'V'];
    const logPrintAddr = Module.findExportByName(null, "__android_log_print");
    if(logPrintAddr === null) return;
    Interceptor.attach(logPrintAddr, {
        onEnter: function(args) {
            let msglevel: string | number = args[0].toInt32();
            if(level >= msglevel) {
                let tag = args[1].readCString();
                let fmtstr = args[2].readCString() as string;
                if(msglevel < levelstrs.length) msglevel = levelstrs[msglevel];
                console.log(`[${msglevel} : ${tag}]`, cprintf(fmtstr, args, 3));
            }
        }
    });
}


interface libCallback {
    (inited: boolean) : void
};
let monitor_libs: {
    libname: string,
    callback: libCallback;
}[] = [];
let call_constructors: InvocationListener;
/**
 * callback will be called when library loaded.  
 * callback(false) when .init_array funcs not called,  
 * callback(true) after.  
 */
export function libraryOnLoad(libname: string, callback: libCallback) {
    monitor_libs.push({libname, callback});
    if(call_constructors !== undefined) return;

    const address = DebugSymbol.findFunctionsNamed("__dl__ZN6soinfo17call_constructorsEv")[0];
    let work_around_b_24465209 = true;
    if (Process.arch == "arm64") work_around_b_24465209 = false;
    const callbacks: {
        [index: string]: libCallback
    } = {};
    call_constructors = Interceptor.attach(address, {
        onEnter: function(args) {
            let soinfo: NativePointer;
            if(Process.arch == "ia32")
                soinfo = (this.context as Ia32CpuContext).eax;
            else
                soinfo = args[0];
            let libname: string | null;
            if(work_around_b_24465209) {
                libname = soinfo.readCString() as string;
            } else if(Process.arch == "arm64") {
                // link_map_head.l_name
                libname = soinfo.add(27*8).readPointer().readCString() as string;
            }
            else libname = "";
            const tid = Process.getCurrentThreadId();
            for(let i in monitor_libs) {
                let tohook = monitor_libs[i].libname;
                if(libname.indexOf(tohook) >= 0) {
                    console.log(`[${tid}] ${libname}'s initproc catched.`);
                    callbacks[tid] = monitor_libs[i].callback;
                    callbacks[tid](false);
                }
            }
        },
        onLeave: function() {
            const tid = Process.getCurrentThreadId();
            if(callbacks[tid] !== undefined) {
                callbacks[tid](true);
                delete callbacks[tid];
            }
        }
    });
    // Interceptor.attach(Module.getExportByName(null, "dlopen"), {
    //     onLeave: function() {
    //         const tid = Process.getCurrentThreadId();
    //         if(callbacks[tid] !== undefined) {
    //             callbacks[tid](true);
    //             delete callbacks[tid];
    //         }
    //     }
    // });
}

const nullCallBack = new NativeCallback(() => 0, 'int', []);
/**
 * when gadget already injected and use server, this should be called.
 */
export function avoidConflict(gadgetName = "libadirf.so") {
    if(easy_frida.isServer) {
        libraryOnLoad(gadgetName, function(inited) {
            if(inited) return;
            const initseg = findElfSegment(gadgetName, ".init_array");
            if(initseg === null) return;
            Memory.protect(initseg.addr, initseg.size, 'rw-');
            for(let offset = 0; offset < initseg.size; offset += Process.pointerSize) {
                let fptr = initseg.addr.add(offset).readPointer();
                if(fptr.isNull()) break;
                initseg.addr.add(offset).writePointer(nullCallBack);
            }
        });
    }
}

export function adbLog(...args: any[]) {
    Java.perform(function() {
        const Log = Java.use("android.util.Log");
        let logstr = "";
        args.forEach(a => {
            if(a && a.toString) logstr += a.toString() + " ";
        });
        Log.d("frida", logstr);
    });
}

/**
 * log click and activity resume event
 */
export function logScreen() { Java.perform(function() {
    const View = Java.use("android.view.View");
    const Activity = Java.use("android.app.Activity");
    
    function getViewIdStr(view: any) {
        let r = view.mResources.value;
        let idstr = view.$className;
        let id = view.getId();
        idstr += "@"+id.toString(16);
        try {
            idstr += ":" + r.getResourceTypeName(id)+"/"+r.getResourceEntryName(id);
        } catch {}
        return idstr;
    }

    View.performClick.implementation = function() {
        let listener = this.getListenerInfo().mOnClickListener.value;
        let myidstr = getViewIdStr(this);
        if(listener) console.log(`[Screen] ${listener.$className}.onClick(${myidstr})`);
        else console.log(`[Screen] None.onClick(${myidstr})`);
        return this.performClick.apply(this, arguments);
    }
    
    // View.dispatchVisibilityChanged.implementation = function(changedView, visibility) {
    //     if(visibility === 0) { // VISIBLE
    //         let logmsg = getViewIdStr(changedView);
    //         if(changedView.getAttachedActivity() !== null) {
    //             logmsg = changedView.getAttachedActivity().$className + " -> " + logmsg;
    //         }
    //         console.log("show:", logmsg);
    //     }
    //     return this.dispatchVisibilityChanged(changedView, visibility);
    // }
    
    Activity.onResume.implementation = function() {
        console.log(`[Screen] ${this.$className}.onResume`);
        return this.onResume.apply(this, arguments);
    }
});}

/**
 * call setWebContentsDebuggingEnabled when WebView created.
 */
export function debugWebView() { Java.perform(function() {
    const WebView = Java.use("android.webkit.WebView");
    WebView.$init.overload(
      'android.content.Context', 
      'android.util.AttributeSet', 
      'int', 'int', 'java.util.Map', 'boolean').implementation = function(...args: any[]) {
        WebView.setWebContentsDebuggingEnabled(true);
        console.log("WebView.setWebContentsDebuggingEnabled called");
        return this.$init.apply(this, args);
    }
});}

// ref: cs.android.com
// system/core/libunwindstack/include/unwindstack/Ucontext{arch}.h
// system/core/libunwindstack/include/unwindstack/Machine{arch}.h
// only setup regs.
function toUContext(context: any) {
    let padsize = 0;
    let nregs = 0;
    if(Process.arch === 'arm') {
        padsize = 8*Process.pointerSize;
        nregs = 16;
    } else if(Process.arch === 'arm64') {
        padsize = 6*Process.pointerSize + 128;
        nregs = 32;
    }
    const result = Memory.alloc(padsize + nregs*Process.pointerSize);
    let regsptr = result.add(padsize);
    let i;
    for(i = 0; i < nregs - 3; ++i) {
        regsptr.add(i*Process.pointerSize).writePointer(context["r"+i]);
    }
    
    if(Process.arch === 'arm') {
        regsptr.add((i+1)*Process.pointerSize).writePointer(context["sp"]);
        regsptr.add((i)*Process.pointerSize).writePointer(context["lr"]);
        regsptr.add((i+2)*Process.pointerSize).writePointer(context["pc"]);
    }
    else if(Process.arch === 'arm64') { // ??? wtf
        regsptr.add(i*Process.pointerSize).writePointer(context["lr"]);
        regsptr.add((i+1)*Process.pointerSize).writePointer(context["sp"]);
        regsptr.add((i+2)*Process.pointerSize).writePointer(context["pc"]);
    }
    return result;
}

let libBacktrace: Module | null = null;
let backtracers: {
    [index: string]: NativePointer
} = {};
const tmpStdString = Memory.alloc(0x20);
tmpStdString.writeByteArray(new Array(0x20).fill(0));
/**
 * show backtrace using libbacktrace in android.
 */
export function showBacktrace(tidOrContext?: number | CpuContext) {
    let tid, context;
    let BacktraceCreate: any;
    let Unwind: any;
    let FormatFrameData: any;
    if(libBacktrace === null) {
        libBacktrace = Process.findModuleByName("libbacktrace.so");
        if(libBacktrace === null)
            libBacktrace = Module.load("libbacktrace.so");
        if(libBacktrace === null) {
            console.log("libbacktrace.so not found");
            return;
        }

        if(Process.arch === 'arm') {
            // Backtrace.Create
            BacktraceCreate = makefunction("libbacktrace.so", "_ZN9Backtrace6CreateEiiP12BacktraceMap", 
                    'pointer', ['int', 'int', 'pointer']);
            // BacktraceCurrent.Unwind
            Unwind = makefunction("libbacktrace.so", "_ZN16BacktraceCurrent6UnwindEjPv", 
                    'bool', ['pointer', 'int', 'pointer']);
            // Backtrace.FormatFrameData
            FormatFrameData = makefunction("libbacktrace.so", "_ZN9Backtrace15FormatFrameDataEj", 
                'pointer', ['pointer', 'pointer', 'int']);
        }
        else if(Process.arch === 'arm64') {
            // Backtrace.Create
            BacktraceCreate = makefunction("libbacktrace.so", "_ZN9Backtrace6CreateEiiP12BacktraceMap", 
                    'pointer', ['int', 'int', 'pointer']);
            // BacktraceCurrent.Unwind
            Unwind = makefunction("libbacktrace.so", "_ZN16BacktraceCurrent6UnwindEmPv", 
                    'bool', ['pointer', 'int', 'pointer']);
            // Backtrace.FormatFrameData
            FormatFrameData = makefunction("libbacktrace.so", "_ZN9Backtrace15FormatFrameDataEm", 
                'pointer', ['pointer', 'pointer', 'int']);
        }
    }
    if(tidOrContext === undefined) {
        tid = Process.getCurrentThreadId();
        context = ptr(0);
    }
    else if(typeof(tidOrContext) === "number") {
        tid = tidOrContext;
        context = ptr(0);
    } else {
        tid = Process.getCurrentThreadId();
        try {
            context = toUContext(tidOrContext);
        }
        catch(e) {
            console.log(e);
            context = ptr(0); 
        }
    }
    if(backtracers[tid] === undefined) {
        const backtracer = BacktraceCreate(Process.id, tid, ptr(0));
        
        Object.defineProperty(backtracer, "Unwind", {
            value: function(ctx: NativePointer) {
                return Unwind(backtracer, 0, ctx);
            }
        });
        Object.defineProperty(backtracer, "FormatFrameData", {
            value: function(str: NativePointer, i: number) {
                return FormatFrameData(str, backtracer, i);
            }
        });
        backtracers[tid] = backtracer;
    }
    const threadBacktracer: any = backtracers[tid];
    const ret = threadBacktracer.Unwind(context);
    if(!ret) {
        console.log("UnwindFromContext failed");
        return;
    }
    let i = 0;
    while(1) {
        threadBacktracer.FormatFrameData(tmpStdString, i);
        const frameMsg = readStdString(tmpStdString);
        if(frameMsg === "") break;
        console.log(frameMsg);
        i += 1;
    }
}

export enum DumpType {
    NativeBacktrace,
    Tombstone,
    JavaBacktrace,
    AnyIntercept
};
let _dump_backtrace_to_file: NativeFunction | null = null;
const open = makefunction("libc.so", "open", 'int', ['string', 'int', 'int']);
const close = makefunction("libc.so", "close", 'int', ['int']);
/**
 * dump backtrace using libdebuggerd_client.
 */
export function dumpBacktraceToFile(tid: number, type: DumpType, outfile: string) {
    if(_dump_backtrace_to_file === null) {
        let address = Module.findExportByName("libdebuggerd_client.so", "_Z22dump_backtrace_to_filei17DebuggerdDumpTypei");
        if(address === null) return;
        _dump_backtrace_to_file = new NativeFunction(address, 'int', ['uint', 'int', 'int']);
    }
    // O_CREAT | O_WRONLY, 0644
    const fd = open(outfile, 65, 420) as number;
    _dump_backtrace_to_file(tid, type, fd);
    close(fd);
}