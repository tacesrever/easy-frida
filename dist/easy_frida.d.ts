import frida from 'frida';
import { REPLCommand, REPLCommandAction } from 'repl';
export default class EasyFrida {
    target: number | string | string[];
    location: 'usb' | 'local' | 'remote';
    targetos: 'win' | 'linux' | 'android' | 'ios';
    remoteAddr?: string;
    enableDebugger: boolean;
    enableChildGating: boolean;
    enableSpawnGating: boolean;
    resumeAfterScriptLoaded: boolean;
    ioEncoding: BufferEncoding | 'gbk';
    logFile?: string;
    onMessage: frida.ScriptMessageHandler;
    device?: frida.Device;
    compileOptions: any;
    private baseDir;
    private agentProjectDir;
    private outFile;
    private curProc;
    private procList;
    private interacting;
    private fridaRepl;
    private scopeCount;
    private prompt;
    private remoteEvalCallbacks;
    private compiler;
    private compilationStarted;
    constructor(target: number | string | string[], location: 'usb' | 'local' | 'remote', targetos: 'win' | 'linux' | 'android' | 'ios', remoteAddr?: string);
    run(target?: string | number | string[]): Promise<boolean>;
    Input(data: Buffer, target?: number): Promise<void>;
    attach: (target?: string | number | string[]) => Promise<boolean>;
    attachOrRun(target?: string | number | string[]): Promise<boolean>;
    rerun(): void;
    /**
     * Attach to or spawn the target and inject ts/js file into it.
     */
    inject(file: string, target?: string | number | string[]): Promise<void>;
    resume(pid?: number): void;
    getDevice(): Promise<frida.Device>;
    private attachToSession;
    /**
     * reload this.outFile in all attached processes.
     */
    reload(): Promise<void>;
    /**
     * compile a js/ts file use frida-compile, options can be set by modify this.compileOptions
     * @param file path of the js/ts file
     * @output will at this.outFile
     */
    compile(file: string): Promise<void>;
    onCompileDiagnostics: (diagnostics: any[]) => void;
    onCompileStarting: () => void;
    onCompileFinished: () => void;
    /**
     * Load a single js file into current attached process
     * @param file path of the js file, default is this.outFile
     * @note (now) There can only be one js file loaded into one process, if there has been one, the old one will be unload.
     */
    load: (file?: string) => Promise<void>;
    /**
     * Attach to or spawn the target, then start a watcher to compile ts/js file and load it into current attached processes.
     * @param file path of main ts/js file
     * @param target target process name, default is this.target
     */
    watch(file: string, target?: string | number | string[]): Promise<void>;
    /**
     * Start a repl that can eval jscode in remote frida attached process. Use `!jscode` to eval code at local, in which `this` will be the EasyFrida instance.
     * @param finallyKill When exit from repl, target will be killed if true, otherwize only detach. Default value is false.
     */
    interact(finallyKill?: boolean): Promise<void>;
    /**
     * Used to add new `.`-prefixed commands to the REPL instance. Such commands are invoked
     * by typing a `.` followed by the `keyword`.
     *
     * @param keyword The command keyword (_without_ a leading `.` character).
     * @param command The function to invoke when the command is processed.
     *
     * @see https://nodejs.org/dist/latest-v10.x/docs/api/repl.html#repl_replserver_definecommand_keyword_cmd
     */
    defineCommand: (keyword: string, command: REPLCommand | REPLCommandAction) => void;
    private replCommands;
    private localEval;
    /**
     * eval jscode in frida agent.
     *
     * @param code jscode
     * @return eval result
     */
    remoteEval: (code: string) => Promise<any>;
    private onChild;
    private onSpawn;
    private onCrashed;
    private onOutput;
    private log;
    /**
     * Detach from all attached process
     */
    detach(): Promise<void>;
    /**
     * Kill all attached process
     */
    kill(): Promise<void>;
    private _onMessage;
    private updatePrompt;
}
