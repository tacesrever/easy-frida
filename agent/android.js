
function real(obj) {
    if(Java.available && obj && obj.$className) {
        return Java.cast(obj, Java.use(obj.$className));
    }
    return obj;
}
exports.real = real;

function backtrace () { if(Java.available) {
    const androidUtilLog = Java.use('android.util.Log');
    const javaLangException = Java.use('java.lang.Exception');
    log(androidUtilLog.getStackTraceString(javaLangException.$new()));
}}
exports.backtrace = backtrace;

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
    View.performClick.implementation = function() {
        let listener = this.getListenerInfo().mOnClickListener.value;
        let r = this.mResources.value;
        let myidstr = this.$className;
        let id = this.getId();
        if(id > 0 && r && r.resourceHasPackage(id)) {
            myidstr += "@"+id.toString(16)+":";
            myidstr += r.getResourceTypeName(id)+"/"+r.getResourceEntryName(id);
        }
        if(listener) console.log(`[Screen] ${listener.$className}.onClick(${myidstr})`);
        else log(`[Screen] None.onClick(${myidstr})`);
        return this.performClick.apply(this, arguments);
    }
    
    Activity.onResume.implementation = function() {
        log(`[Screen] ${this.$className}.onResume`);
        return this.onResume.apply(this, arguments);
    }
});}
exports.logScreen = logScreen;