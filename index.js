
const fs = require('fs');
const path = require('path');
const util = require('util');
const repl = require('repl');
const crypto = require('crypto');
const process = require('process');
const readline = require('readline');
const child_process = require('child_process');

const AsyncLock = require('async-lock');
const frida = require('frida');
// OSDEP
const shell_tools = require("./shell_tools.js");
const adb_shell = shell_tools.adb_shell;
const adb_push = shell_tools.adb_push;

const agentDir = path.join(__dirname, "agent");
const lock = new AsyncLock();

function md5(file) {
    let data = fs.readFileSync(file);
    let hash = crypto.createHash('md5');
    hash.update(data);
    return hash.digest('hex');
}

async function sleep(ms) {
	return new Promise(resolve => setTimeout(resolve, ms));
}

function compile(fileName) {
    let hash = md5(fileName);
    let lasthash;
    try {
        lasthash = fs.readFileSync(path.join(agentDir, "lasthash"));
    } catch (e) {
        lasthash = '';
    }
    if(hash == lasthash) {
        return true;
    }
    console.log("\ncompiling script...");
    fs.copyFileSync(fileName, path.join(agentDir, "main.js"));
    try {
        child_process.execSync("npm run build", {cwd: agentDir});
    } catch(e) {
        console.log(e);
        return false;
    }
    fs.writeFileSync(path.join(agentDir, "lasthash"), hash);
    console.log("compile done.");
    return true;
}

class EasyFrida {
    constructor(target, location='usb', targetOs='android', remoteAddr=null) {
        this.target = target;
        this.location = location;
        this.targetOs = targetOs;
        this.remoteAddr = remoteAddr;
        this.procList = [];
        this.curProc = {session:null, script:null, onDetach:null};
        this.device = null;
        this.logfile = null;
        this.scriptfile = null;
        this.isInteract = false;
        this.repl = null;
        this.interactLabels = {
            clear:          "\r                         \r",
            local:          "local nodejs > ",
            remote:         "remote (global) > ",
            remoteLocal:    "remote (localenv) > "
        }
        this.interactLabel = this.interactLabels.local;
        
        switch(location) {
            case 'usb':
                this.getDevice = frida.getUsbDevice;
                break;
            case 'local':
                this.getDevice = frida.getLocalDevice;
                break;
            case 'remote':
                this.getDevice = frida.getRemoteDevice;
                break;
        }
        
        // OSDEP
        switch(targetOs) {
            case 'android':
                this.serverDir = '/data/local/tmp/';
                this.server = 'adirf';
        }
    }
    
    async run(target = this.target, enableChildGating) {
        await this._setupDevice();
        await this.startServer();
        this._onLog(`spawning ${target}`);
        const pid = await this.device.spawn(target).catch(async e => {
            await this.restartServer();
            this.run(target, enableChildGating);
        });
        if(pid) await this.attach(target, enableChildGating);
    }
    
    async attach(target = this.target, enableChildGating) {
        await this._setupDevice();
        await this.startServer();
        const session = await this.device.attach(target);
        console.log(`[+] attached to ${session.pid}.`);
        if(enableChildGating) session.enableChildGating();
        const tproc = {session:null, script:null, onDetach:null};
        tproc.session = session;
        
        tproc.onDetach = async () => {
            let idx = this.procList.indexOf(tproc);
            if(idx < 0) return;
            this._onLog(`[!] ${tproc.session.pid}'s session detached.`);
            this.procList.splice(idx, 1);
            if(this.curProc === tproc && this.procList.length) {
                this.curProc = this.procList[0];
                this._onLog(`[+] switched to ${this.curProc.session.pid}.`);
            } else {
                this.curProc = {session:null, script:null, onDetach:null};
                this.interactLabel = this.interactLabels.local;
                if(this.repl) this.repl.setPrompt(this.interactLabel);
                this._onLog(`[!] all session detached.`);
            }
        }
        session.detached.connect(tproc.onDetach);
        this.procList.push(tproc);
        this.curProc = tproc;
        this.interactLabel = this.interactLabels.remote;
        if(this.repl) {
            this._onLog("[+] enter remote env. use `!code` to eval code at local.");
            this.repl.setPrompt(this.interactLabel);
        }
    }
    
    async inject(file = this.scriptfile, target = this.target, enableChildGating) {
        this.scriptfile = file;
        await this.attach(target, enableChildGating).catch( async () => {
            await this.run(target, enableChildGating);
        });
        this.load(file)
            .catch( e => {console.log(e);})
            .then( () => {this.resume();});
    }
    
    resume(pid) {
        if(pid === undefined) 
            this.device.resume(this.curProc.session.pid).catch(()=>{});
        else
            this.device.resume(pid).catch(()=>{});
    }
    
    async watch(file = this.scriptfile, target = this.target, enableChildGating) {
        await this.inject(file, target, enableChildGating);
        let timer = null;
        fs.watch(file, async () => {
            // avoid reload when script's local eval loop running.
            if(this.interactLabel === this.interactLabels.remoteLocal) {
                while(this.interactLabel === this.interactLabels.remoteLocal) await sleep(1000);
            }
            if(timer === null)
                timer = setTimeout(() => { this.reload(file); timer = null; }, 200);
        });
    }
    
    async reload(file = this.scriptfile) {
        if(this.procList.length) {
            lock.acquire("reload", async () => {
                const curpid = this.curProc.session.pid;
                for(let i in this.procList) {
                    this.curProc = this.procList[i];
                    await this.load(file);
                }
                
                for(let i in this.procList) {
                    if(this.procList[i].session.pid == curpid) {
                        this.curProc = this.procList[i];
                        break;
                    }
                }
                
                if(this.procList.length !== 0) {
                    this.interactLabel = this.interactLabels.remote;
                    if(this.repl) this.repl.setPrompt(this.interactLabel);
                }
                
                this._onLog("");
            });
        }
    }
    
    async load(file = this.scriptfile) {
        this.scriptfile = file;
        const curProc = this.curProc;
        lock.acquire('compile', async () => {
            if(!compile(file)) throw "compile failed";
        });
        const source = fs.readFileSync(require.resolve("./_main.js"), "utf-8");
        
        // const script = await curProc.session.createScript(source, {runtime: 'v8'});
        const script = await curProc.session.createScript(source);
        script.logHandler = this._onConsoleMessage.bind(this);
        script.message.connect(this._onMessage.bind(this));
        // script.destroyed.connect();
        
        let oldscript = this.curProc.script;
        if(oldscript) {
            // oldscript.destroyed.disconnect();
            await oldscript.unload();
        }
        
        this.curProc.script = script;
        await script.load();
    }
    
    async interact(finallyKill = false) {
        this.isInteract = true;
        this.forceLocalEval = false;
        process.on('SIGINT', () => {});
        
        const logCallback = ((e, msg) => {
            if(e)
                this._onLog(e.stack);
            if(msg)
                this._onLog(msg);
        }).bind(this);
        
        async function _ieval(code, context, filename, callback) {
            let usedCallback = callback;
            if(callback.name === 'finish') {
                usedCallback = logCallback;
            }
            this._interactCallback = usedCallback;
            code = code.trim();
            if(code == "") {
                this._onLog("");
                return;
            }
            try {
                // TODO: list and switch sessions in this.procList.
                if(this.forceLocalEval) {
                    usedCallback(null, eval(code));
                    return;
                }
                if(code[0] == '!') {
                    usedCallback(null, eval(code.substr(1)));
                    return;
                }
                
                switch(this.interactLabel) {
                    case this.interactLabels.remoteLocal:
                        await this.post({"type":"scope", "code":code});
                        break;
                    case this.interactLabels.remote:
                        usedCallback(null, await this.reval(code));
                        break;
                    case this.interactLabels.local:
                        usedCallback(null, eval(code));
                        break;
                }
            }
            catch(e) {
                if (e.name == 'SyntaxError' && /^(Unexpected end of input|Unexpected token)/.test(e.message)) {
                    return callback(new repl.Recoverable(e));
                }
                usedCallback(e); 
            }
        }
        
        let ieval = _ieval.bind(this);
        
        const simpleExpressionRE = /.*\.?$/;
        // const simpleExpressionRE = /(?:[a-zA-Z_$](?:\w|\$)*\.)*[a-zA-Z_$](?:\w|\$)*\.?$/;
        
        function buildGetKeysCode(expr) {
            let getKeysCode = "";
            if(expr.substr(0, 2) === 'j:') {
                getKeysCode = 'j:';
                expr = expr.substr(2);
            }
            getKeysCode += `var _replobj = ${expr};`
            getKeysCode += "Object.getOwnPropertyNames(_replobj)";
            getKeysCode += ".concat(Object.getOwnPropertyNames(_replobj.__proto__))";
            return getKeysCode;
        }
        
        // ref: https://github.com/nodejs/node/blob/master/lib/repl.js function complete
        function remoteCompleter(line, callback) {
            let groups = [];
            let completeOn, group, filter, match;
            
            line = line.trimLeft();
            
            // if(match = line.match(JavaClassRE)) {
                // let classname = match[1];
                // ...
            // } else 
            if (line.length === 0 || /\w|\.|\$/.test(line[line.length - 1])) {
                match = simpleExpressionRE.exec(line);
                if (line.length !== 0 && !match) {
                    groupsLoaded();
                    return;
                }
                let expr;
                completeOn = (match ? match[0] : '');
                if (line.length === 0) {
                    filter = '';
                    expr = '';
                } else if (line[line.length - 1] === '.') {
                    filter = '';
                    expr = match[0].slice(0, match[0].length - 1);
                } else {
                    const bits = match[0].split('.');
                    filter = bits.pop();
                    expr = bits.join('.');
                }
                const mGroups = [];
                
                function replCallback(e, names) {
                    if(names instanceof Array)
                        mGroups.push(names);
                    if (!expr || expr === 'j:') {
                        groups = mGroups;
                        groupsLoaded();
                        return;
                    }
                    if (mGroups.length) {
                        for (let i = 0; i < mGroups.length; i++) {
                            groups.push(mGroups[i].map( member => `${expr}.${member}`));
                        }
                        if (filter) {
                            filter = `${expr}.${filter}`;
                        }
                    }
                    groupsLoaded();
                }
                let javaenv = false;
                if (!expr || expr === 'j:') {
                    ieval(buildGetKeysCode("global"), null, null, replCallback);
                    return;
                }
                const evalExpr = buildGetKeysCode(expr);
                ieval(evalExpr, null, null, replCallback);
                return;
                
            }
            groupsLoaded();
            function groupsLoaded() {
                // Filter, sort (within each group), uniq and merge the completion groups.
                if (groups.length && filter) {
                    const newGroups = [];
                    for (let i = 0; i < groups.length; i++) {
                        if(groups[i] instanceof Array) {
                            group = groups[i].filter((elem) => elem.indexOf(filter) === 0);
                            if (group.length) {
                                newGroups.push(group);
                            }
                        }
                    }
                    groups = newGroups;
                }
                
                const completions = [];
                // Unique completions across all groups.
                const uniqueSet = new Set(['']);
                // Completion group 0 is the "closest" (least far up the inheritance
                // chain) so we put its completions last: to be closest in the REPL.
                for (const group of groups) {
                    group.sort((a, b) => (b > a ? 1 : -1));
                    const setSize = uniqueSet.size;
                    for (const entry of group) {
                        if (!uniqueSet.has(entry)) {
                            completions.unshift(entry);
                            uniqueSet.add(entry);
                        }
                    }
                    // Add a separator between groups.
                    if (uniqueSet.size !== setSize) {
                        completions.unshift('');
                    }
                }

                // Remove obsolete group entry, if present.
                if (completions[0] === '') {
                    completions.shift();
                }
                callback(null, [completions, completeOn]);
            }
        }
        
        if(this.interactLabel != this.interactLabels.local) {
            this._onLog("[+] enter remote env. use `!code` to eval code at local.");
        }
        this.repl = repl.start({
            prompt:this.interactLabel,
            ignoreUndefined: true,
            eval:ieval
        });
        
        this.repl.setupHistory(".easy_frida_history", (e, r) => {});
        
        let localCompleter = this.repl.completer;
        this.repl.completer = (line, callback) => {
            if(this.interactLabel == this.interactLabels.local)
                localCompleter(line, callback);
            else if (line[0] == '!') {
                    // localCompleter will call eval('try { expr } catch {}')
                    // to get local object, when our interactLabel isn't local.
                    // so force local here.
                    this.forceLocalEval = true;
                    localCompleter(line.substr(1), (r, groups) => {
                        this.forceLocalEval = false;
                        callback(r, groups);
                    });
                }
            else
                remoteCompleter(line, callback);
        }
        
        function onExit() {
            try {
                if(finallyKill) {
                    this.kill().then( () => { process.exit(); });
                }
                else {
                    this.detach().then( () => { process.exit(); });
                }
            }
            catch(e) {
                console.log(e);
                process.exit();
            }
        }
        this.repl.on('exit', onExit.bind(this));
    }
    
    async _setupDevice() {
        if(!this.device) {
            this.device = await this.getDevice({ timeout: null });
        }
        this.device.childAdded.connect(this._onChild);
        this.device.processCrashed.connect(this._onCrashed);
    }
    // OSDEP
    async startServer() {
        if (this.location == 'usb') {
            await this.device.getProcess(this.server).catch(async e => {
                this._onLog("[+] starting server...");
                adb_shell(`cd ${this.serverDir};nohup ${this.serverDir}${this.server} \\&`, 1).catch(()=>{});
            });
        }
    }
    
    async stopServer() {
        // OSDEP
        if (this.location == 'usb') {
            await adb_shell(`pkill -f ${this.server}`, 1);
        }
    }
    
    connect() {
        // OSDEP
        if(this.location === 'usb' && this.remoteAddr) {
            child_process.execSync(`adb connect ${this.remoteAddr}`);
            // sometimes first try will fail.
            child_process.execSync(`adb connect ${this.remoteAddr}`);
        }
    }
    
    async restartServer() {
        await this.detach();
        await this.stopServer();
        // OSDEP
        await adb_shell("pkill -f zygote");
        await sleep(10000);
        this.connect();
        await this.startServer();
    }
    
    async _onChild(child) {
        await this.attach(child.pid);
        await this.load().catch( e => {console.log(e);});
        this.resume(child.pid);
    }
    
    _onCrashed(crash) {
        // pid processName summary report parameters
        console.log("");
        console.log(crash.summary);
        console.log(crash.report);
        console.log(crash.parameters);
    }
    
    _onLog(message) {
        if(this.logfile) {
            if(typeof(message) === 'object') {
                
            }
            else {
                fs.writeFileSync(this.logfile, message.toString(), { flag: 'a' });
            }
        }
        if(this.isInteract) {
            process.stdout.write(this.interactLabels.clear);
        }
        console.log(message);
        if(this.isInteract) {
            process.stdout.write(this.interactLabel);
        }
    }
    
    _onConsoleMessage(level, text) {
        this._onLog(text);
    }
    
    _onMessage(message, data) {
        switch (message.type) {
            case frida.MessageType.Send:
                const payload = message.payload;
                switch(payload.type) {
                    case "scope":
                        if(payload.act == "enter") {
                            this.interactLabel = this.interactLabels.remoteLocal;
                            if(this.repl) this.repl.setPrompt(this.interactLabel);
                        }
                        else if (payload.act == "quit") {
                            this.interactLabel = this.interactLabels.remote;
                            if(this.repl) this.repl.setPrompt(this.interactLabel);
                        }
                        else if (payload.act == "result") {
                            this._interactCallback(null, payload.result);
                        }
                        break;
                    case "rpc":
                        // TODO
                    default:
                        console.log(this.interactLabels.clear, payload);
                        break;
                }
                break;
            case frida.MessageType.Error:
                console.log("");
                console.log(message.description);
                console.log(message.stack);
                break;
            default:
        }
    }
    
    async detach() {
        for(let i in this.procList) {
            this.procList[i].session.detached.disconnect(this.procList[i].onDetach);
            await this.procList[i].session.detach().catch(()=>{});
        }
        
        this.procList = [];
        this.curProc = {session:null, script:null, onDetach:null};
    }
    
    async kill() {
        if(this.procList.length) {
            console.log("\nkilling", this.target);
            for(let i in this.procList) {
                await this.device.kill(this.procList[i].session.pid).catch(()=>{});
            }
            // OSDEP
            if(this.targetOs == "android") {
                await adb_shell(`am kill ${this.target}`, 1).catch(()=>{});
                await adb_shell(`am force-stop ${this.target}`, 1).catch(()=>{});
            }
            this.procList = [];
            this.curProc = {session:null, script:null, onDetach:null};
        }
    }
    
    async modify() {
        let target = this.target;
        // OSDEP
        if(typeof target == 'string') {
            let scriptDir = "/data/local/tmp/fscripts/";
            let config = {"filter": { "executables" : [ target ] } };
            await adb_push(require.resolve("./_main.js"), `${scriptDir}${target}.js`, 1);
            await adb_shell(`chmod 0644 ${scriptDir}${target}.js`, 1);
            fs.writeFileSync(`${target}.config`, JSON.stringify(config));
            await adb_push(`${target}.config`, `${scriptDir}${target}.config`, 1)
            await adb_shell(`chmod 0644 ${scriptDir}${target}.config`, 1)
        }
    }
    
    async removeModify() {
        let target = this.target;
        // OSDEP
        if(typeof target == 'string') {
            let scriptDir = "/data/local/tmp/fscripts/";
            await adb_shell(`rm ${scriptDir}${target}.*`, 1);
        }
    }
    
    async post(msg, data=null) {
        return this.curProc.script.post(msg, data);
    }
    
    async reval(code) {
        return this.curProc.script.exports.exec(code);
    }
    
    
}

module.exports = EasyFrida;