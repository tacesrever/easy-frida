declare global {
    interface String {
        toMatchPattern(): string;
    }
}

Object.defineProperty(String.prototype, "toMatchPattern", {
    value: function() {
        let pattern = [];
        for(let i in this) {
            pattern.push(this.charCodeAt(i).toString(16));
        }
        return pattern.join(' ');
    }
});

export let interact: string = '\
if(typeof disableInteract === "undefined" || disableInteract === false) {\
    global.disableInteract = false;\
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
        send({"type":"scope", "act":"result", "result":result});\
    }\
    send({"type":"scope", "act":"quit"});\
    console.log("[+] Quit local scope.");\
}\
'

export function rpcCall(funcName: string, args: any, noreturn?: boolean): Promise<any> {
    return new Promise(resolve => {
        send({"type": "rpc", "function": funcName, "args": args, "noreturn": noreturn});
        if(noreturn) resolve(null);

        recv(funcName + '_ret', function(message) {
            resolve(message["ret"]);
        });
    });
}

export let isServer: boolean;
let agentName = 'frida-agent';
if(Process.pointerSize === 4) agentName += '-32';
else if(Process.pointerSize === 8) agentName += '-64';
switch(Process.platform) {
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
if(Process.findModuleByName(agentName) !== null) isServer = true;

const globalEval = eval;
rpc.exports.exec = (code: string) => {
    return new Promise(resolve => {
        let result;
        if (code.substr(0, 2) !== "j:") {
            try { result = globalEval(code) } catch(e) { result = e.stack }
            resolve(result);
        } else {
            setImmediate(() => { Java.perform(function () {
                try { result = globalEval(code.substr(2)) } catch(e) { result = e.stack }
                resolve(result);
            })});
        }
    });
}