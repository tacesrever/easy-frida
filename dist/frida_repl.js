import repl from 'repl';
const LocalEvalPrefix = '!';
const JavaPerformPrefix = 'j:';
const SimpleExpressionRE = /.*\.?$/;
export class FridaRepl {
    localEval;
    remoteEval;
    onResult;
    useLocalEval = true;
    repl;
    constructor(localEval, remoteEval, onResult) {
        this.localEval = localEval;
        this.remoteEval = remoteEval;
        this.onResult = onResult;
    }
    start() {
        this.repl = repl.start({
            ignoreUndefined: true,
            eval: this.replEval
        });
        const localCompleter = this.repl.completer;
        Object.defineProperty(this.repl, "completer", {
            value: (line, callback) => {
                if (this.useLocalEval) {
                    localCompleter.call(this.repl, line, callback);
                }
                else if (line.startsWith(LocalEvalPrefix)) {
                    // localCompleter will call eval('try { expr } catch {}')
                    // to get local object, when our interactLabel isn't local.
                    // so force local here.
                    this.useLocalEval = true;
                    localCompleter.call(this.repl, line.substring(LocalEvalPrefix.length), (r, groups) => {
                        this.useLocalEval = false;
                        callback(r, groups);
                    });
                }
                else {
                    this.remoteCompleter(line, callback);
                }
            }
        });
        return this.repl;
    }
    replEval = (code, context, filename, originalCallback) => {
        const callback = originalCallback.name === 'finish' ? this.evalCallback : originalCallback;
        code = code.trim();
        if (code === "") {
            this.onResult("");
            return;
        }
        try {
            if (this.useLocalEval) {
                callback(null, this.localEval(code));
                return;
            }
            if (code.startsWith(LocalEvalPrefix)) {
                callback(null, this.localEval(code.substring(LocalEvalPrefix.length)));
                return;
            }
            this.remoteEval(code).then(result => {
                callback(null, result);
            });
        }
        catch (e) {
            if (e.name == 'SyntaxError' && /^(Unexpected end of input|Unexpected token)/.test(e.message)) {
                return originalCallback(new repl.Recoverable(e));
            }
            callback(e);
        }
    };
    // ref: https://github.com/nodejs/node/blob/master/lib/repl.js function complete
    remoteCompleter = (line, callback) => {
        let groups = [];
        let completeOn, expr, filter, match;
        line = line.trimStart();
        if (line.length === 0 || /\w|\.|\$/.test(line[line.length - 1])) {
            match = SimpleExpressionRE.exec(line);
            if (line.length !== 0 && !match) {
                groupsLoaded();
                return;
            }
            completeOn = (match ? match[0] : '');
            if (line.length === 0) {
                filter = '';
                expr = '';
            }
            else if (line[line.length - 1] === '.') {
                filter = '';
                expr = match[0].slice(0, match[0].length - 1);
            }
            else {
                const bits = match[0].split('.');
                filter = bits.pop();
                expr = bits.join('.');
            }
            if (!expr || expr === JavaPerformPrefix) {
                this.replEval(buildGetKeysCode("global"), null, null, replCallback);
                return;
            }
            this.replEval(buildGetKeysCode(expr), null, null, replCallback);
            return;
        }
        groupsLoaded();
        function replCallback(e, names) {
            try {
                names = JSON.parse(names);
            }
            catch (e) { }
            ;
            try {
                const mGroups = [];
                if (names instanceof Array)
                    mGroups.push(names);
                if (!expr || expr === JavaPerformPrefix) {
                    groups = mGroups;
                    groupsLoaded();
                    return;
                }
                if (mGroups.length) {
                    for (let i = 0; i < mGroups.length; i++) {
                        groups.push(mGroups[i].map(member => `${expr}.${member}`));
                    }
                    if (filter) {
                        filter = `${expr}.${filter}`;
                    }
                }
            }
            catch { }
            ;
            groupsLoaded();
        }
        function groupsLoaded() {
            // Filter, sort (within each group), uniq and merge the completion groups.
            if (groups.length && filter) {
                const newGroups = [];
                for (let i = 0; i < groups.length; i++) {
                    if (groups[i] instanceof Array) {
                        let group = groups[i].filter((elem) => elem.indexOf(filter) === 0);
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
        function buildGetKeysCode(expr) {
            let getKeysCode = "";
            if (expr.startsWith(JavaPerformPrefix)) {
                getKeysCode = JavaPerformPrefix;
                expr = expr.substring(JavaPerformPrefix.length);
            }
            getKeysCode += `var _replobj = ${expr};`;
            getKeysCode += "var _replkeys = Object.getOwnPropertyNames(_replobj);";
            getKeysCode += "for(var p = _replobj.__proto__; p !== null; p = p.__proto__) { ";
            getKeysCode += "_replkeys = _replkeys.concat(Object.getOwnPropertyNames(p));";
            getKeysCode += "};";
            getKeysCode += "_replkeys;";
            return getKeysCode;
        }
    };
    evalCallback = (err, result) => {
        if (err) {
            this.onResult(err.stack);
        }
        if (result !== undefined) {
            this.onResult(result);
        }
    };
}
//# sourceMappingURL=frida_repl.js.map