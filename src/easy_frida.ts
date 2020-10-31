
import fs = require('fs');
import path = require('path');
import process = require('process');
import { format } from 'util';

import AsyncLock = require('async-lock');
import frida = require('frida');
import compiler = require('frida-compile');

import { FridaRepl } from './frida_repl';
import { REPLCommand, REPLCommandAction, ReplOptions, REPLServer } from 'repl';

const lock = new AsyncLock();
const sleep = (time: number) => new Promise((resolve) => setTimeout(resolve, time));
interface FridaProcess {
    session: frida.Session
    script: frida.Script
    scopelist: string[]
    scopeid: string
    name?: string
    onDetach: () => void
}

export default class EasyFrida {
    compileOptions = {
        bytecode: false,
        sourcemap: true,
        compress: true,
        useAbsolutePaths: true
    }
    baseDir = process.cwd()
    agentProjectDir = path.join(this.baseDir, "agent/")
    outFile = path.join(this.baseDir, "agent.js")
    logFile?: string
    scriptFile?: string
    device?: frida.Device
    enableChildGating = false
    enableSpawnGating = false
    enableDebugger = false
    onMessage: frida.ScriptMessageHandler = null
    private curProc: FridaProcess = null
    private procList: FridaProcess[] = []
    private interacting = false
    private fridaRepl: FridaRepl
    private scopeCount = 0
    private prompt: string
    private remoteEvalCallbacks: {
        [index: string]: (result: any) => void
    } = {}
    private watcher: any
    constructor(public target: number | string, public location: 'usb' | 'local' | 'remote', public targetos: 'win' | 'linux' | 'android' | 'ios', public remoteAddr?: string) {
    }

    run(target = this.target): Promise<boolean> {
        if(typeof(target) === 'number') {
            return this.attach(target);
        }
        return new Promise(resolve => {
            this.getDevice()
            .then(device => {
                this.log(`[+] Spawning ${target}...`);

                device.spawn(target)
                .then(pid => {
                    this.attach(pid).then(ret => {
                        this.curProc.name = target;
                        resolve(ret);
                    });
                })
                .catch(e => {
                    this.log(`[!] Spawn failed: ${e.message}`);
                    resolve(false);
                })
            })
        });
    }

    attach = (target = this.target): Promise<boolean> => {
        return new Promise((resolve, reject) => {
            this.getDevice().then(device => {
                device.attach(target).then(sess => {
                    this.attachToSession(sess);
                    if(typeof(target) === 'string') {
                        this.curProc.name = target;
                        this.updatePrompt();
                    }
                    resolve(true);
                })
                .catch(e => {
                    if(e.message.indexOf('Ambiguous name') >= 0) {
                        this.log(e.message);
                        const pid = e.message.match(/pid\: (\d+)/)[1];
                        this.log(`[!] Attaching to ${pid} ...`);
                        this.device.attach(parseInt(pid)).then(sess => {
                            this.attachToSession(sess);
                            resolve(true);
                        });
                    }
                    reject(e);
                })
            });
        });
    }

    attachOrRun(target = this.target): Promise<boolean> {
        return new Promise(resolve => {
            this.attach(target).then(resolve)
            .catch(e => {
                if(e.message === "Process not found")
                    this.run(target).then(resolve);
                else {
                    this.log("[!] Attach Error: " + e.message);
                    resolve(false);
                }
            });
        });
    }

    rerun() {
        this.run().then(() => {this.reload();});
    }

    /**
     * Attach to or spawn the target and inject ts/js file into it.
     */
    inject(file = this.scriptFile, target = this.target) {
        return this.attachOrRun(target).then(attached => {
            if(attached) {
                this.compile(file)
                .then(() => this.load())
                .then(() => this.resume())
            }
        }).catch(this.log)
    }

    resume(pid?: number) {
        if(pid === undefined) 
            this.device.resume(this.curProc.session.pid).catch(()=>{});
        else
            this.device.resume(pid).catch(()=>{});
    }

    getDevice(): Promise<frida.Device> {
        return new Promise(resolve => {
            if(this.device !== undefined) {
                resolve(this.device);
                return;
            }

            const getDeviceCallback = (device: frida.Device) => {
                this.device = device;
                device.childAdded.connect(this.onChild);
                device.processCrashed.connect(this.onCrashed);
                device.spawnAdded.connect(this.onSpawn);
                if(this.enableSpawnGating) device.enableSpawnGating();
                resolve(device);
            }
            switch(this.location) {
                case 'local':
                    frida.getLocalDevice().then(getDeviceCallback);
                    break;
                case 'remote':
                    frida.getDeviceManager().addRemoteDevice(this.remoteAddr).then(getDeviceCallback);
                    break;
                case 'usb':
                    frida.getUsbDevice({timeout: null}).then(getDeviceCallback);
                    break;
            }
        });
    }

    private attachToSession = (session: frida.Session) => {
        if(this.enableChildGating) session.enableChildGating();
        if(this.enableDebugger) session.enableDebugger();

        this.log(`[+] Attached to ${session.pid}.`);
        
        const tmpProc: FridaProcess = Object.create(null);
        tmpProc.session = session;
        tmpProc.scopelist = [];

        tmpProc.onDetach = () => {
            const idx = this.procList.indexOf(tmpProc);
            if(idx < 0) return;
            this.log(`[!] Detached from pid ${tmpProc.session.pid}.`);
            this.procList.splice(idx, 1);
            this.scopeCount -= tmpProc.scopelist.length;

            if(this.procList.length > 0) {
                if(this.curProc === tmpProc) {
                    this.curProc = this.procList[0];
                    this.updatePrompt();
                }
            } else {
                this.curProc = Object.create(null);
                if(this.interacting) {
                    this.fridaRepl.useLocalEval = true;
                    this.updatePrompt();
                }
                this.log(`[!] all detached.`);
            }
        }

        session.detached.connect(tmpProc.onDetach);
        this.procList.push(tmpProc);
        this.curProc = tmpProc;
        if(this.interacting) {
            this.fridaRepl.useLocalEval = false;
            this.updatePrompt();
        }
    }

    /**
     * reload this.outFile in all attached processes.
     */
    async reload() {
        if(this.procList.length > 0) {
            lock.acquire("reload", async () => {
                const curpid = this.curProc.session.pid;
                for(let i in this.procList) {
                    this.curProc = this.procList[i];
                    await this.load();
                }
                
                for(let i in this.procList) {
                    if(this.procList[i].session.pid == curpid) {
                        this.curProc = this.procList[i];
                        break;
                    }
                }
                
                if(this.procList.length !== 0) {
                    this.fridaRepl.useLocalEval = false;
                    this.updatePrompt();
                }
            }, null, null);
        }
    }

    /**
     * compile a js/ts file use frida-compile, options can be set by modify this.compileOptions
     * @param file path of the js/ts file
     * @output will at this.outFile
     */
    compile(file = this.scriptFile) {
        return new Promise(resolve => {
            process.chdir(this.agentProjectDir);
            lock.acquire('compile', async () => {
                await compiler.build(path.join(this.baseDir, file), this.outFile, this.compileOptions)
                .then(resolve)
            }, null, null);
            process.chdir(this.baseDir);
        })
    }

    /**
     * Load a single js file into current attached process
     * @param file path of the js file, default is this.outFile
     * @note (now) There can only be one js file loaded into one process, if there has been one, the old one will be unload.
     */
    async load(file = this.outFile) {
        const curProc = this.curProc;
        const source = fs.readFileSync(file, "utf-8");
        const script = await curProc.session.createScript(source);
        script.logHandler = (level, text) => {
            this.log(text);
        }
        script.message.connect(this._onMessage.bind(this));
        // script.destroyed.connect(() => {
        //     this.log(curProc.session.pid + "'s script destroyed");
        // });
        
        let oldscript = curProc.script;
        if(oldscript) {
            await oldscript.unload();
        }
        
        curProc.script = script;
        await script.load();
    }

    /**
     * Attach to or spawn the target, then start a watcher to compile ts/js file and load it into current attached processes.
     * @param file path of main ts/js file
     * @param target target process name, default is this.target
     */
    async watch(file = this.scriptFile, target = this.target) {
        await this.attachOrRun(target);
        process.chdir(this.agentProjectDir);
        this.watcher = compiler.watch(path.join(this.baseDir, file), this.outFile, this.compileOptions)
        .on('compile', details => {
            const duration = details.duration;
            this.log(`[+] Compile fin (${duration} ms)`);
            if(this.interacting && this.scopeCount > 0) {
                this.log(`[!] can't reload when some script is busy, please quit scope and retry.`);
            } else {
                // wait for flush
                setTimeout(this.reload.bind(this), 50);
            }
        })
        .on('error', error => {
            const message = error.toString();
            this.log(message);
            this.log("[!] Compilation failed.");
        });
        process.chdir(this.baseDir);
        return this.watcher;
    }

    /**
     * Start a repl that can eval jscode in remote frida attached process. Use `!jscode` to eval code at local, in which `this` will be the EasyFrida instance.
     * @param finallyKill When exit from repl, target will be killed if true, otherwize only detach. Default value is false.
     */
    async interact(finallyKill = false) {
        process.on('SIGINT', () => {});
        
        const fridaRepl = new FridaRepl(this.localEval, this.remoteEval, this.log);
        this.interacting = true;
        fridaRepl.start();
        this.fridaRepl = fridaRepl;
        this.updatePrompt();
        
        fridaRepl.repl.setupHistory(path.join(this.baseDir, ".easy_frida_history"), (e, r) => {});
        
        for(const command in this.replCommands) {
            fridaRepl.repl.defineCommand(command, this.replCommands[command]);
        }
        
        fridaRepl.repl.on('exit', onExit.bind(this));
        
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
                this.log(e);
                process.exit();
            }
        }
    }

    /**
     * Used to add new `.`-prefixed commands to the REPL instance. Such commands are invoked
     * by typing a `.` followed by the `keyword`.
     *
     * @param keyword The command keyword (_without_ a leading `.` character).
     * @param command The function to invoke when the command is processed.
     *
     * @see https://nodejs.org/dist/latest-v10.x/docs/api/repl.html#repl_replserver_definecommand_keyword_cmd
     */
    defineCommand = (keyword: string, command: REPLCommand | REPLCommandAction) => {
        this.replCommands[keyword] = command;
        if(this.fridaRepl && this.fridaRepl.repl) {
            this.fridaRepl.repl.defineCommand(keyword, command);
        }
    }

    private replCommands: {
        [command: string] : REPLCommand | REPLCommandAction
    } = {
        "ps": {
            help: "show attached processes",
            action: () => {
                this.procList.forEach(proc => {
                    this.log(`${proc.session.pid} ${proc.name!}`);
                });
            }
        },
        "s": {
            help: "switch to process by pid",
            action: pid => {
                this.procList.forEach(proc => {
                    if(proc.session.pid === parseInt(pid)) {
                        this.curProc = proc;
                        this.updatePrompt();
                    }
                });
            }
        }
    }

    private localEval = (code: string) => {
        return eval(code);
    }

    /**
     * eval jscode in frida agent.  
     * 
     * @param code jscode  
     * @return eval result
     */
    remoteEval = (code: string) => {
        if(!this.curProc.scopeid) {
            return this.curProc.script.exports.eval(code);
        }
        return new Promise(async resolve => {
            this.curProc.script.post({"type":"scope-" + this.curProc.scopeid, "code":code});
            while(this.remoteEvalCallbacks[this.curProc.scopeid] !== undefined) {
                await sleep(500);
            }
            this.remoteEvalCallbacks[this.curProc.scopeid] = resolve;
        });
    }

    private onChild = async (child: frida.Child) => {
        this.log("[+] child process " + child.pid);
        await this.attach(child.pid);
        await this.load();
        this.resume(child.pid);
    }

    private onSpawn = async (spawn: frida.Spawn) => {
        if(typeof(this.target) === 'string' && spawn.identifier.indexOf(this.target) === 0) {
            await this.attach(spawn.identifier);
            await this.load();
        }
        this.resume(spawn.pid);
    }

    private onCrashed = (crash: frida.Crash) => {
        this.log(crash.summary);
        this.log(crash.report);
        this.log(crash.parameters);
    }

    private log = (message: any) => {
        if(this.logFile !== undefined) {
                fs.writeFileSync(this.logFile, format(message) + "\n", { flag: 'a+' });
        }
        if(this.interacting) {
            process.stdout.write("\r" + ' '.repeat(this.prompt.length + this.fridaRepl.repl.line.length) + "\r");
        }
        console.log(message);
        if(this.interacting) {
            process.stdout.write(this.prompt);
            process.stdout.write(this.fridaRepl.repl.line);
        }
    }

    /** 
     * Detach from all attached process
     */
    async detach() {
        for(let i in this.procList) {
            this.procList[i].session.detached.disconnect(this.procList[i].onDetach);
            await this.procList[i].session.detach().catch(()=>{});
        }
        
        this.procList = [];
        this.scopeCount = 0;
        this.curProc = null;
    }

    /** 
     * Kill all attached process
     */
    async kill() {
        if(this.procList.length) {
            console.log("\nkilling", this.target);
            for(let i in this.procList) {
                await this.device.kill(this.procList[i].session.pid).catch(()=>{});
            }
            this.procList = [];
            this.curProc = null;
        }
    }
    
    private _onMessage(message: frida.Message, data: Buffer | null) {
        switch (message.type) {
            case frida.MessageType.Send:
                const payload = message.payload;
                const type: string = payload.type;
                if(type.startsWith("scope-")) {
                    const scopeid = type.substr(6);
                    if(payload.act == "enter") {
                        this.scopeCount += 1;
                        if(this.curProc.session.pid != payload.pid) {
                            for(const proc of this.procList) {
                                if(proc.session.pid == payload.pid) {
                                    this.curProc = proc;
                                    this.log("[+] switch to " + payload.pid);
                                    break;
                                }
                            }
                        }
                        this.curProc.scopelist.push(scopeid);
                        this.curProc.scopeid = scopeid;
                        this.updatePrompt();
                    }
                    else if (payload.act == "quit") {
                        if(this.remoteEvalCallbacks[scopeid]) delete this.remoteEvalCallbacks[scopeid];
                        this.scopeCount -= 1;
                        if(this.curProc.session.pid != payload.pid) {
                            for(const proc of this.procList) {
                                if(proc.session.pid == payload.pid) {
                                    this.curProc = proc;
                                    this.log("[+] switch to " + payload.pid);
                                    break;
                                }
                            }
                        }
                        const id = this.curProc.scopelist.indexOf(scopeid);
                        this.curProc.scopelist.splice(id, 1);
                        this.curProc.scopeid = this.curProc.scopelist[this.curProc.scopelist.length - 1];
                        this.updatePrompt();
                    }
                    else if (payload.act == "result") {
                        this.remoteEvalCallbacks[scopeid](payload.result);
                        delete this.remoteEvalCallbacks[scopeid];
                    }
                }
                else {
                    // switch(payload.type) {
                    //     case "rpc":
                    //         // TODO
                    //     default:
                    //         this.log(payload);
                    //         break;
                    // }
                    if(this.onMessage) {
                        this.onMessage(message, data);
                    } else {
                        this.log(payload);
                    }
                    break;
                }
            break;
            case frida.MessageType.Error:
                if(this.onMessage) {
                    this.onMessage(message, data);
                } else {
                    this.log((message as frida.ErrorMessage).stack);
                }
                break;
        }
    }
    
    private updatePrompt() {
        if(this.fridaRepl === undefined) return;
        
        if(this.fridaRepl.useLocalEval) {
            this.prompt = "[local->nodejs] > ";
        }
        else if(this.curProc.scopeid === undefined) {
            const procid = this.curProc.name? this.curProc.name : this.curProc.session.pid;
            this.prompt = `[${this.device.name}->${procid}] > `;
        }
        else {
            const procid = this.curProc.name? this.curProc.name : this.curProc.session.pid;
            this.prompt = `[${this.device.name}->${procid}->${this.curProc.scopeid}] > `;
        }
        this.fridaRepl.repl.setPrompt(this.prompt);
        this.fridaRepl.repl.displayPrompt();
    }
}