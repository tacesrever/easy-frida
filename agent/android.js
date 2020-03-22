
const easy_frida = require('./easy_frida');
const native = require('./native');
const linux = require('./linux');

function javaBacktrace() { if(Java.available) {
    const androidUtilLog = Java.use('android.util.Log');
    const javaLangException = Java.use('java.lang.Exception');
    console.log(androidUtilLog.getStackTraceString(javaLangException.$new()));
}}
exports.javaBacktrace = javaBacktrace;

let _dump_backtrace_to_file = null;
// type: enum DebuggerdDumpType : uint8_t {
    // kDebuggerdNativeBacktrace,
    // kDebuggerdTombstone,
    // kDebuggerdJavaBacktrace,
    // kDebuggerdAnyIntercept
// };
function dump_backtrace_to_file(tid, type, outname) {
    if(_dump_backtrace_to_file === null) {
        let address = Module.findExportByName("libdebuggerd_client.so", "_Z22dump_backtrace_to_filei17DebuggerdDumpTypei");
        if(address === null) return;
        // tid, type, outfd
        _dump_backtrace_to_file = new NativeFunction(address, 'int', ['uint', 'int', 'int']);
        native.modules.c.open = ['int', ['string', 'int', 'int']];
        native.modules.c.close = ['int', ['int']];
    }
    // O_CREAT | O_WRONLY, 0644
    const fd = native.modules.c.open(outname, 65, 420);
    _dump_backtrace_to_file(tid, type, fd);
    native.modules.c.close(fd);
}

// ref: cs.android.com
// system/core/libunwindstack/include/unwindstack/Ucontext{arch}.h
// system/core/libunwindstack/include/unwindstack/Machine{arch}.h
// only setup regs.
function toUContext(context) {
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

let libBacktrace = null;
let backtracers = {};
const tmpStdString = Memory.alloc(0x20);
function backtrace(tidOrContext) {
    let tid, context;
    let BacktraceCreate, Unwind, FormatFrameData;
    if(libBacktrace === null) {
        if(Process.findModuleByName("libbacktrace.so") === null) Module.load("libbacktrace.so");
        if(Process.findModuleByName("libbacktrace.so") === null) {
            console.log("libbacktrace not found");
            return;
        }
        libBacktrace = native.modules.backtrace;
        
        if(Process.arch === 'arm') {
            // Backtrace.Create
            libBacktrace._ZN9Backtrace6CreateEiiP12BacktraceMap = ['pointer', ['int', 'int', 'pointer']];
            BacktraceCreate = libBacktrace._ZN9Backtrace6CreateEiiP12BacktraceMap;
            // BacktraceCurrent.Unwind
            libBacktrace._ZN16BacktraceCurrent6UnwindEjPv = ['bool', ['pointer', 'int', 'pointer']];
            Unwind = libBacktrace._ZN16BacktraceCurrent6UnwindEjPv;
            // Backtrace.FormatFrameData
            libBacktrace._ZN9Backtrace15FormatFrameDataEj = ['pointer', ['pointer', 'pointer', 'int']];
            FormatFrameData = libBacktrace._ZN9Backtrace15FormatFrameDataEj;
        }
        else if(Process.arch === 'arm64') {
            // Backtrace.Create
            libBacktrace._ZN9Backtrace6CreateEiiP12BacktraceMap = ['pointer', ['int', 'int', 'pointer']];
            BacktraceCreate = libBacktrace._ZN9Backtrace6CreateEiiP12BacktraceMap;
            // BacktraceCurrent.Unwind
            libBacktrace._ZN16BacktraceCurrent6UnwindEmPv = ['bool', ['pointer', 'int', 'pointer']];
            Unwind = libBacktrace._ZN16BacktraceCurrent6UnwindEmPv;
            // Backtrace.FormatFrameData
            libBacktrace._ZN9Backtrace15FormatFrameDataEm = ['pointer', ['pointer', 'pointer', 'int']];
            FormatFrameData = libBacktrace._ZN9Backtrace15FormatFrameDataEm;
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
            value: function(ctx) {
                return Unwind(backtracer, 0, ctx);
            }
        });
        Object.defineProperty(backtracer, "FormatFrameData", {
            value: function(str, i) {
                return FormatFrameData(str, backtracer, i);
            }
        });
        backtracers[tid] = backtracer;
    }
    const threadBacktracer = backtracers[tid];
    const ret = threadBacktracer.Unwind(context);
    if(!ret) {
        console.log("UnwindFromContext failed");
        return;
    }
    let i = 0;
    while(1) {
        threadBacktracer.FormatFrameData(tmpStdString, i);
        const frameMsg = native.readStdString(tmpStdString);
        if(frameMsg === "") break;
        console.log(frameMsg);
        i += 1;
    }
}
exports.backtrace = backtrace;

let monitor_libs = [];
let linker = null;
global.logcatLevel = 0xff;
function showLogcat(showLevel) {
    if(showLevel) logcatLevel = showLevel;
    const levelstrs = ['F', 'E', 'W', 'I', 'D', 'V'];
    Interceptor.attach(Module.findExportByName(null, "__android_log_print"), {
        onEnter: function(args) {
            let level = args[0].toUInt32();
            if(logcatLevel > level) {
                let tag = args[1].readCString();
                let fmtstr = args[2].readCString();
                if(level < levelstrs.length) level = levelstrs[level];
                console.log(`[${level} : ${tag}]`, native.cprintf(fmtstr, args, 3));
            }
            
        }
    });
}
exports.showLogcat = showLogcat;

function libraryOnLoad(libname, fn) {
    // __dl__ZN6soinfo17call_constructorsEv in /system/bin/linker | /system/bin/linker64
    const addr_arm = 0x1A63D;
    const addr_arm64 = 0x2FAC4;
    const addr_ia32 = 0x2DE8;
    let work_around_b_24465209;
    
    monitor_libs.push([libname, fn]);
    let call_constructors;
    if(linker == null) {
        if(Process.arch == "arm") {
            linker = Process.findModuleByName("linker");
            call_constructors = linker.base.add(addr_arm);
            work_around_b_24465209 = true;
        } else if (Process.arch == "arm64") {
            linker = Process.findModuleByName("linker64");
            call_constructors = linker.base.add(addr_arm64);
            work_around_b_24465209 = false;
        } else if (Process.arch == "ia32") {
            linker = Process.findModuleByName("linker");
            call_constructors = linker.base.add(addr_ia32);
            work_around_b_24465209 = true;
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
                let libname;
                if(work_around_b_24465209) {
                    libname = soinfo.readCString();
                } else if(Process.arch == "arm64") {
                    // link_map_head.l_name
                    libname = soinfo.add(27*8).readPointer().readCString();
                }
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

// for case gadget is globally injected,
// sometimes it will suspend when use server at same time.
function avoidConflict() {
    function diableGadgets() {
        const fridaGadget = Process.findModuleByName("libadirf.so");
        const initseg = linux.findElfSegment(fridaGadget, ".init_array");
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

function forEachObj(clzinst, fn) {
    if(Java.available && clzinst && clzinst.$className) {
        Java.choose(clzinst.$className, {
            onMatch: function(inst) {
                fn(inst);
            },
            onComplete: function() {}
        });
    }
}

function adblog() { let args = arguments; Java.perform(function() {
    const Log = Java.use("android.util.Log");
    const JavaString = Java.use("java.lang.String");
    let logstr = "";
    for(let i in args) {
        if(args[i] && args[i].toString) logstr += args[i].toString() + " ";
    }
    Log.d("frida", logstr);
});}

function logScreen() { Java.perform(function() {
    const View = Java.use("android.view.View");
    const Activity = Java.use("android.app.Activity");

    function getViewIdStr(view) {
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
exports.logScreen = logScreen;

function debugWebView() { Java.perform(function() {
    const WebView = Java.use("android.webkit.WebView");
    WebView.$init.overload(
      'android.content.Context', 
      'android.util.AttributeSet', 
      'int', 'int', 'java.util.Map', 'boolean').implementation = function() {
        WebView.setWebContentsDebuggingEnabled(true);
        console.log("WebView.setWebContentsDebuggingEnabled called");
        return this.$init.apply(this, arguments);
    }
});}
exports.debugWebView = debugWebView;
