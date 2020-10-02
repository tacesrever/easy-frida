"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.traceSyscallByStalkerAt = void 0;
// TODO
function traceSyscallByStalkerAt(addr) {
    const once = Interceptor.attach(addr, function () {
        once.detach();
        Interceptor.flush();
        let syscallMnemonics;
        // dep on arch and platform's combines
        let beforeSyscall, afterSyscall;
        switch (Process.arch) {
            case 'arm':
            case 'arm64':
                syscallMnemonics = ['svc'];
                break;
            case 'ia32':
            case 'x64':
                syscallMnemonics = ['syscall', 'int'];
                break;
            default:
                syscallMnemonics = [];
        }
        let trace = false;
        const tid = Process.getCurrentThreadId();
        const targetBase = Process.findRangeByAddress(addr).base;
        Stalker.follow(tid, {
            transform: function (iterator) {
                const startInst = iterator.next();
                let inst = startInst;
                if (!trace) {
                    const range = Process.findRangeByAddress(inst.address);
                    if (range && targetBase.equals(range.base))
                        trace = true;
                    else {
                        while (inst !== null) {
                            iterator.keep();
                            inst = iterator.next();
                        }
                        return;
                    }
                }
                while (inst !== null) {
                    if (syscallMnemonics.indexOf(inst.mnemonic) >= 0) {
                        iterator.putCallout(beforeSyscall);
                        iterator.keep();
                        iterator.putCallout(afterSyscall);
                    }
                    else {
                        iterator.keep();
                    }
                    inst = iterator.next();
                }
            }
        });
    });
}
exports.traceSyscallByStalkerAt = traceSyscallByStalkerAt;
//# sourceMappingURL=syscall.js.map