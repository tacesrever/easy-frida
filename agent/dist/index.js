"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isServer = exports.rpcCall = exports.interact = void 0;
Object.defineProperty(String.prototype, "toMatchPattern", {
    value: function () {
        let pattern = [];
        for (let i in this) {
            pattern.push(this.charCodeAt(i).toString(16));
        }
        return pattern.join(' ');
    }
});
exports.interact = '\
if(typeof disableInteract === "undefined" || disableInteract === false) {\
    global.disableInteract = false;\
    var interactCode, result, eventType = "scope";\
    if(typeof scopeid !== "undefined") eventType += "-" + scopeid.toString();\
    else eventType = "scope-tid-" + Process.getCurrentThreadId();\
    send({"type":eventType, "act":"enter", "pid": Process.id});\
    console.log("[+] Enter local scope, input /q to exit.");\
    while(true) {\
        var codeRecv = recv(eventType, function(message) {\
            interactCode = message["code"];\
        });\
        codeRecv.wait();\
        if(interactCode == "/q") break;\
        try {\
            result = eval(interactCode);\
            if(typeof result === "object")\
                result = JSON.stringify(result, function(key, value) {\
                    if (key !== "" && typeof value === "object" && value !== null) {\
                            if(value.toString !== undefined) return value.toString();\
                            return;\
                    }\
                    return value;\
                }, " ");\
        } catch(e) {\
            result = e.stack;\
        }\
        send({"type":eventType, "act":"result", "result":result, "pid": Process.id});\
    }\
    send({"type":eventType, "act":"quit", "pid": Process.id});\
    console.log("[+] Quit local scope.");\
}\
';
function rpcCall(funcName, args, noreturn) {
    return new Promise(resolve => {
        send({ "type": "rpc", "function": funcName, "args": args, "noreturn": noreturn });
        if (noreturn)
            resolve(null);
        recv(funcName + '_ret', function (message) {
            resolve(message["ret"]);
        });
    });
}
exports.rpcCall = rpcCall;
let agentName = 'frida-agent';
if (Process.pointerSize === 4)
    agentName += '-32';
else if (Process.pointerSize === 8)
    agentName += '-64';
switch (Process.platform) {
    case 'windows':
        agentName += '.dll';
        break;
    case 'linux':
    case 'qnx':
        agentName += '.so';
        break;
    case 'darwin':
        agentName += '.dylib';
        break;
}
if (Process.findModuleByName(agentName) !== null)
    exports.isServer = true;
const globalEval = eval;
rpc.exports.exec = (code) => {
    return new Promise(resolve => {
        let result;
        if (code.substr(0, 2) !== "j:") {
            try {
                result = globalEval(code);
            }
            catch (e) {
                result = e.stack;
            }
            resolve(result);
        }
        else {
            setImmediate(() => {
                Java.perform(function () {
                    try {
                        result = globalEval(code.substr(2));
                    }
                    catch (e) {
                        result = e.stack;
                    }
                    resolve(result);
                });
            });
        }
    });
};
//# sourceMappingURL=index.js.map