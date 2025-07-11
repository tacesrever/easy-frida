"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Input = exports.DumpType = void 0;
exports.showJavaBacktrace = showJavaBacktrace;
exports.javaBacktrace = javaBacktrace;
exports.showJavaCaller = showJavaCaller;
exports.showLogcat = showLogcat;
exports.showlibevents = showlibevents;
exports.libraryOnLoad = libraryOnLoad;
exports.avoidConflict = avoidConflict;
exports.adbLog = adbLog;
exports.logScreen = logScreen;
exports.debugWebView = debugWebView;
exports.showBacktrace = showBacktrace;
exports.dumpBacktraceToFile = dumpBacktraceToFile;
exports.showDialog = showDialog;
exports.getNativeAddress = getNativeAddress;
exports.cast = cast;
exports.objToSimpleString = objToSimpleString;
exports.traceClass = traceClass;
const index_js_1 = require("./index.js");
const native_js_1 = require("./native.js");
const linux_js_1 = require("./linux.js");
const frida_java_bridge_1 = __importDefault(require("frida-java-bridge"));
globalThis.Java = frida_java_bridge_1.default;
function showJavaBacktrace() {
    console.log(javaBacktrace());
}
function javaBacktrace() {
    const androidUtilLog = frida_java_bridge_1.default.use('android.util.Log');
    const exception = frida_java_bridge_1.default.use('java.lang.Exception').$new();
    return androidUtilLog.getStackTraceString(exception);
}
function showJavaCaller() {
    const backtrace = javaBacktrace();
    console.log(backtrace.split("\n")[2]);
}
/**
 * show android log at console.
 */
function showLogcat(level = 255) {
    const levelstrs = ['F', 'E', 'W', 'I', 'D', 'V'];
    const logPrintAddr = Module.findGlobalExportByName("__android_log_print");
    if (logPrintAddr === null)
        return;
    Interceptor.attach(logPrintAddr, {
        onEnter: function (args) {
            let msglevel = args[0].toInt32();
            if (level >= msglevel) {
                const tid = Process.getCurrentThreadId();
                const tag = args[1].readCString();
                const fmtstr = args[2].readCString();
                if (msglevel < levelstrs.length)
                    msglevel = levelstrs[msglevel];
                console.log(`[${tid}-${msglevel}:${tag}]`, (0, native_js_1.cprintf)(fmtstr, args, 3));
            }
        }
    });
}
;
let monitor_libs = [];
let call_constructors;
/**
 * callback will be called when library loaded.
 * callback(false) when .init_array funcs not called,
 * callback(true) after.
 */
const sleep = (0, native_js_1.importfunc)("libc.so", "sleep", "void", ["int"]);
function showlibevents(timeout = 0) {
    const address = DebugSymbol.getFunctionByName("__dl__ZN6soinfo17call_constructorsEv");
    let work_around_b_24465209 = true;
    if (Process.arch == "arm64")
        work_around_b_24465209 = false;
    Interceptor.attach(address, {
        onEnter: function (args) {
            let soinfo, base;
            if (Process.arch == "ia32")
                soinfo = this.context.eax;
            else
                soinfo = args[0];
            let libname;
            if (work_around_b_24465209) {
                libname = soinfo.readCString();
                base = soinfo.add(128 + 3 * Process.pointerSize).readPointer();
            }
            else if (Process.arch == "arm64") {
                base = soinfo.add(2 * 8).readPointer();
                // link_map_head.l_name
                libname = soinfo.add(27 * 8).readPointer().readCString();
            }
            else
                libname = "";
            const tid = Process.getCurrentThreadId();
            this.tid = tid;
            this.libname = libname;
            console.log(`[${tid}] init ${libname} ${base}`);
            if (timeout == -1)
                eval(index_js_1.interact);
            else if (timeout > 0)
                sleep(timeout);
        },
        onLeave: function () {
            console.log(`[${this.tid}] ${this.libname} init finished`);
            if (timeout == -1)
                eval(index_js_1.interact);
            else if (timeout > 0)
                sleep(timeout);
        }
    });
}
function libraryOnLoad(libname, callback) {
    monitor_libs.push({ libname, callback });
    if (call_constructors !== undefined)
        return;
    const address = DebugSymbol.findFunctionsNamed("__dl__ZN6soinfo17call_constructorsEv")[0];
    let work_around_b_24465209 = true;
    if (Process.arch == "arm64")
        work_around_b_24465209 = false;
    const callbacks = {};
    call_constructors = Interceptor.attach(address, {
        onEnter: function (args) {
            let soinfo;
            if (Process.arch == "ia32")
                soinfo = this.context.eax;
            else
                soinfo = args[0];
            let libname;
            if (work_around_b_24465209) {
                libname = soinfo.readCString();
            }
            else if (Process.arch == "arm64") {
                // link_map_head.l_name
                libname = soinfo.add(27 * 8).readPointer().readCString();
            }
            else
                libname = "";
            const tid = Process.getCurrentThreadId();
            for (let i in monitor_libs) {
                let tohook = monitor_libs[i].libname;
                if (libname.indexOf(tohook) >= 0) {
                    console.log(`[${tid}] ${libname}'s initproc catched.`);
                    callbacks[tid] = monitor_libs[i].callback;
                    callbacks[tid](false);
                }
            }
        },
        onLeave: function () {
            const tid = Process.getCurrentThreadId();
            if (callbacks[tid] !== undefined) {
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
function avoidConflict(gadgetName = "libadirf.so") {
    if (index_js_1.isServer) {
        libraryOnLoad(gadgetName, function (inited) {
            if (inited)
                return;
            const initseg = (0, linux_js_1.findElfSegment)(gadgetName, ".init_array");
            if (initseg === null)
                return;
            Memory.protect(initseg.addr, initseg.size, 'rw-');
            for (let offset = 0; offset < initseg.size; offset += Process.pointerSize) {
                let fptr = initseg.addr.add(offset).readPointer();
                if (fptr.isNull())
                    break;
                initseg.addr.add(offset).writePointer(nullCallBack);
            }
        });
    }
}
const android_log_print = (0, native_js_1.importfunc)(null, "__android_log_print", 'int', ['int', 'string', 'string']);
function adbLog(...args) {
    let logstr = "";
    args.forEach(a => {
        if (a && a.toString)
            logstr += a.toString() + " ";
    });
    android_log_print(4, "frida", logstr);
}
/**
 * log click and activity resume event
 */
function logScreen() {
    frida_java_bridge_1.default.perform(function () {
        const View = frida_java_bridge_1.default.use("android.view.View");
        const Activity = frida_java_bridge_1.default.use("android.app.Activity");
        function getViewIdStr(_view) {
            let view = frida_java_bridge_1.default.cast(_view, View);
            let r = view.mResources.value;
            let idstr = view.$className;
            let id = view.getId();
            idstr += "@" + id.toString(16);
            try {
                idstr += ":" + r.getResourceTypeName(id) + "/" + r.getResourceEntryName(id);
            }
            catch { }
            return idstr;
        }
        View.performClick.implementation = function () {
            let listener = this.getListenerInfo().mOnClickListener.value;
            let myidstr = getViewIdStr(this);
            if (listener)
                console.log(`[Screen] ${listener.$className}.onClick(${myidstr})`);
            else
                console.log(`[Screen] None.onClick(${myidstr})`);
            return this.performClick.apply(this, arguments);
        };
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
        Activity.onResume.implementation = function () {
            console.log(`[Screen] ${this.$className}.onResume`);
            return this.onResume.apply(this, arguments);
        };
    });
}
/**
 * call setWebContentsDebuggingEnabled when WebView created.
 */
function debugWebView() {
    frida_java_bridge_1.default.perform(function () {
        const WebView = frida_java_bridge_1.default.use("android.webkit.WebView");
        WebView.$init.overload('android.content.Context', 'android.util.AttributeSet', 'int', 'int', 'java.util.Map', 'boolean').implementation = function (...args) {
            WebView.setWebContentsDebuggingEnabled(true);
            console.log("WebView.setWebContentsDebuggingEnabled called");
            return this.$init.apply(this, args);
        };
    });
}
// ref: cs.android.com
// system/core/libunwindstack/include/unwindstack/Ucontext{arch}.h
// system/core/libunwindstack/include/unwindstack/Machine{arch}.h
// only setup regs.
function toUContext(context) {
    let padsize = 0;
    let nregs = 0;
    if (Process.arch === 'arm') {
        padsize = 8 * Process.pointerSize;
        nregs = 16;
    }
    else if (Process.arch === 'arm64') {
        padsize = 6 * Process.pointerSize + 128;
        nregs = 32;
    }
    const result = Memory.alloc(padsize + nregs * Process.pointerSize);
    let regsptr = result.add(padsize);
    let i;
    for (i = 0; i < nregs - 3; ++i) {
        regsptr.add(i * Process.pointerSize).writePointer(context["r" + i]);
    }
    if (Process.arch === 'arm') {
        regsptr.add((i + 1) * Process.pointerSize).writePointer(context["sp"]);
        regsptr.add((i) * Process.pointerSize).writePointer(context["lr"]);
        regsptr.add((i + 2) * Process.pointerSize).writePointer(context["pc"]);
    }
    else if (Process.arch === 'arm64') { // ??? wtf
        regsptr.add(i * Process.pointerSize).writePointer(context["lr"]);
        regsptr.add((i + 1) * Process.pointerSize).writePointer(context["sp"]);
        regsptr.add((i + 2) * Process.pointerSize).writePointer(context["pc"]);
    }
    return result;
}
let libBacktrace = null;
let backtracers = {};
const tmpStdString = Memory.alloc(0x20);
tmpStdString.writeByteArray(new Array(0x20).fill(0));
/**
 * show backtrace using libbacktrace in android.
 */
function showBacktrace(tidOrContext) {
    let tid, context;
    let BacktraceCreate;
    let Unwind;
    let FormatFrameData;
    if (libBacktrace === null) {
        libBacktrace = Process.findModuleByName("libbacktrace.so");
        if (libBacktrace === null)
            libBacktrace = Module.load("libbacktrace.so");
        if (libBacktrace === null) {
            console.log("libbacktrace.so not found");
            return;
        }
        if (Process.arch === 'arm') {
            // Backtrace.Create
            BacktraceCreate = (0, native_js_1.importfunc)("libbacktrace.so", "_ZN9Backtrace6CreateEiiP12BacktraceMap", 'pointer', ['int', 'int', 'pointer']);
            // BacktraceCurrent.Unwind
            Unwind = (0, native_js_1.importfunc)("libbacktrace.so", "_ZN16BacktraceCurrent6UnwindEjPv", 'bool', ['pointer', 'int', 'pointer']);
            // Backtrace.FormatFrameData
            FormatFrameData = (0, native_js_1.importfunc)("libbacktrace.so", "_ZN9Backtrace15FormatFrameDataEj", 'pointer', ['pointer', 'pointer', 'int']);
        }
        else if (Process.arch === 'arm64') {
            // Backtrace.Create
            BacktraceCreate = (0, native_js_1.importfunc)("libbacktrace.so", "_ZN9Backtrace6CreateEiiP12BacktraceMap", 'pointer', ['int', 'int', 'pointer']);
            // BacktraceCurrent.Unwind
            Unwind = (0, native_js_1.importfunc)("libbacktrace.so", "_ZN16BacktraceCurrent6UnwindEmPv", 'bool', ['pointer', 'int', 'pointer']);
            // Backtrace.FormatFrameData
            FormatFrameData = (0, native_js_1.importfunc)("libbacktrace.so", "_ZN9Backtrace15FormatFrameDataEm", 'pointer', ['pointer', 'pointer', 'int']);
        }
    }
    if (tidOrContext === undefined) {
        tid = Process.getCurrentThreadId();
        context = ptr(0);
    }
    else if (typeof (tidOrContext) === "number") {
        tid = tidOrContext;
        context = ptr(0);
    }
    else {
        tid = Process.getCurrentThreadId();
        try {
            context = toUContext(tidOrContext);
        }
        catch (e) {
            console.log(e);
            context = ptr(0);
        }
    }
    if (backtracers[tid] === undefined) {
        const backtracer = BacktraceCreate(Process.id, tid, ptr(0));
        Object.defineProperty(backtracer, "Unwind", {
            value: function (ctx) {
                return Unwind(backtracer, 0, ctx);
            }
        });
        Object.defineProperty(backtracer, "FormatFrameData", {
            value: function (str, i) {
                return FormatFrameData(str, backtracer, i);
            }
        });
        backtracers[tid] = backtracer;
    }
    const threadBacktracer = backtracers[tid];
    const ret = threadBacktracer.Unwind(context);
    if (!ret) {
        console.log("UnwindFromContext failed");
        return;
    }
    let i = 0;
    while (1) {
        threadBacktracer.FormatFrameData(tmpStdString, i);
        const frameMsg = (0, native_js_1.readStdString)(tmpStdString);
        if (frameMsg === "")
            break;
        console.log(frameMsg);
        i += 1;
    }
}
var DumpType;
(function (DumpType) {
    DumpType[DumpType["NativeBacktrace"] = 0] = "NativeBacktrace";
    DumpType[DumpType["Tombstone"] = 1] = "Tombstone";
    DumpType[DumpType["JavaBacktrace"] = 2] = "JavaBacktrace";
    DumpType[DumpType["AnyIntercept"] = 3] = "AnyIntercept";
})(DumpType || (exports.DumpType = DumpType = {}));
;
let _dump_backtrace_to_file = null;
const open = (0, native_js_1.importfunc)("libc.so", "open", 'int', ['string', 'int', 'int']);
const close = (0, native_js_1.importfunc)("libc.so", "close", 'int', ['int']);
/**
 * dump backtrace using libdebuggerd_client.
 */
function dumpBacktraceToFile(tid, type, outfile) {
    if (_dump_backtrace_to_file === null) {
        let m = Process.findModuleByName("libdebuggerd_client.so");
        if (!m)
            return;
        let address = m.findSymbolByName("_Z22dump_backtrace_to_filei17DebuggerdDumpTypei");
        if (address === null)
            return;
        _dump_backtrace_to_file = new NativeFunction(address, 'int', ['uint', 'int', 'int']);
    }
    // O_CREAT | O_WRONLY, 0644
    const fd = open(outfile, 65, 420);
    _dump_backtrace_to_file(tid, type, fd);
    close(fd);
}
function showDialog(activityContext, message) {
    frida_java_bridge_1.default.scheduleOnMainThread(function () {
        const AlertDialogBuilder = frida_java_bridge_1.default.use("android.app.AlertDialog$Builder");
        const JavaString = frida_java_bridge_1.default.use("java.lang.String");
        const builder = AlertDialogBuilder.$new(activityContext);
        const s = JavaString.$new(message);
        builder.setMessage(s);
        builder.create().show();
    });
}
function getNativeAddress(methodWarpper) {
    let params = methodWarpper._p;
    if (params === undefined && methodWarpper._o) {
        if (methodWarpper._o.length === 1)
            params = methodWarpper._o[0]._p;
        else
            throw "muti overloads";
    }
    if (params === undefined) {
        throw "not a methodWarpper";
    }
    const [methodName, classWrapper, type, methodId, retType, argTypes] = params;
    if (Process.arch === "arm64")
        return methodId.add(0x18).readPointer();
    console.log("not impl");
    (0, native_js_1.d)(methodId);
    eval(index_js_1.interact);
}
function cast(obj) {
    if (obj instanceof Object && obj.$className) {
        return frida_java_bridge_1.default.cast(obj, frida_java_bridge_1.default.use(obj.$className));
    }
    return obj;
}
function objToSimpleString(obj) {
    let resultStr = "";
    if (obj === 0)
        return "0";
    if (obj === "")
        return "";
    if (obj === null)
        return "null";
    if (obj === undefined)
        return "undefined";
    if (obj && obj.toString) {
        resultStr = cast(obj).toString();
    }
    if (resultStr.indexOf('\n') !== -1) {
        resultStr = resultStr.substring(0, resultStr.indexOf('\n')) + "...";
    }
    if (resultStr.length > 50) {
        resultStr = resultStr.substring(0, 50) + "...";
    }
    return resultStr;
}
function traceClass(className) {
    const clz = frida_java_bridge_1.default.use(className);
    const methods = clz.class.getDeclaredMethods();
    for (const method of methods) {
        const methodName = method.getName();
        const argTypes = method.getParameterTypes().map(t => t.getName());
        clz[methodName].overload(...argTypes).implementation = function (...args) {
            console.log(`${className}.${methodName}(${args.map(a => objToSimpleString(a)).join(", ")})`);
            let result = this[methodName](...args);
            console.log(`${className}.${methodName}(${args.map(a => objToSimpleString(a)).join(", ")}) => ${objToSimpleString(result)}`);
            return result;
        };
    }
    return {
        detach: () => {
            for (const method of methods) {
                const methodName = method.getName();
                const argTypes = method.getArgumentTypes().map(t => t.getName());
                clz[methodName].overload(...argTypes).implementation = null;
            }
        }
    };
}
// rewrite from /system/framework/input.jar
var Input;
(function (Input) {
    function tap(coords) {
        frida_java_bridge_1.default.perform(() => {
            const MotionEvent = frida_java_bridge_1.default.use("android.view.MotionEvent");
            const InputManager = frida_java_bridge_1.default.use("android.hardware.input.InputManager");
            const SystemClock = frida_java_bridge_1.default.use("android.os.SystemClock");
            const touchscreenInputSource = 0x1002;
            const deviceId = getInputDeviceId(touchscreenInputSource);
            function randInt(max) {
                return Math.floor(Math.random() * max);
            }
            const now = SystemClock.uptimeMillis();
            function injectTap(x, y) {
                const eventDown = MotionEvent.obtain(now, now, 0, x, y, 1.0, 1.0, 0, 1.0, 1.0, deviceId, 0);
                const upTime = now + 5 + randInt(10);
                const eventUp = MotionEvent.obtain(now, upTime, 1, x, y, 0.0, 1.0, 0, 1.0, 1.0, deviceId, 0);
                eventDown.setSource(touchscreenInputSource);
                eventDown.setDisplayId(0);
                eventUp.setSource(touchscreenInputSource);
                eventUp.setDisplayId(0);
                InputManager.getInstance().injectInputEvent(eventDown, 0);
                InputManager.getInstance().injectInputEvent(eventUp, 0);
            }
            coords.forEach(coord => {
                injectTap(coord.x, coord.y);
            });
        });
    }
    Input.tap = tap;
    ;
    function getInputDeviceId(inputSource) {
        const InputDevice = frida_java_bridge_1.default.use("android.view.InputDevice");
        const devIds = InputDevice.getDeviceIds();
        for (let i = 0; i < devIds.length; ++i) {
            let id = devIds[i];
            if (InputDevice.getDevice(id).supportsSource(inputSource))
                return id;
        }
    }
})(Input || (exports.Input = Input = {}));
//# sourceMappingURL=android.js.map