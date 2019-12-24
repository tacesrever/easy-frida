
// const util = require('util');
// global.util = util;

const global_eval = eval;
rpc.exports.exec = async function (code) {
    return new Promise((resolve, reject) => {
        let result;
        if (code.substr(0, 2) == "j:") {
            setImmediate(() => {
                Java.perform(function () {
                    try {
                        result = global_eval(code.substr(2));
                    } catch(e) {
                        result = e;
                    }
                    resolve(result);
                });
            });
        } else {
            try {
                result = global_eval(code);
            } catch(e) {
                result = e;
            }
            resolve(result);
        }
    });
}

exports.interact = '\
    var interactCode;\
    var result;\
    send({"type":"scope", "act":"enter"});\
    console.log("[+] Enter local scope, input /q to exit.");\
    while(true) {\
        var codeRecv = recv("scope", function(message) {\
            interactCode = message["code"];\
        });\
        codeRecv.wait();\
        if(interactCode == "/q") break;\
        try {\
            result = eval(interactCode);\
        } catch(e) {\
            result = e;\
        }\
        send({"type":"scope", "act":"result", "result":result});\
    }\
    send({"type":"scope", "act":"quit"});\
    console.log("[+] Quit local scope.");\
'

function bufToArr(arrayBuffer) {
    return Array.prototype.slice.call(new Uint8Array(arrayBuffer));
}
exports.bufToArr = bufToArr;

function rpcCall(fname, args, noreturn, fn) {
    if(noreturn) noreturn = true;
    else noreturn = false;
    send({"type":"rpc", "function":fname, "args":args, "noreturn": noreturn});
    if(noreturn) return;
    
    if(fn) {
        recv(fname+'_ret', function(message) {
            fn(message["ret"]);
        });
        return;
    }
    let ret;
    let rpcret = recv(fname+'_ret', function(message) {
        ret = message["ret"];
    });
    rpcret.wait();
    return ret;
}
exports.rpcCall = rpcCall;

function nullfunc() {
    return 0;
}
exports.nullfunc = nullfunc;
let nullcb = new NativeCallback(nullfunc, 'int', []);
exports.nullcb = nullcb;

