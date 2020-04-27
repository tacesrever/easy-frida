# easy-frida
a simple tool for easyily dev/debug using frida and write module for agent. (mainly used for android)

# Notice
in dev, not a clone-then-use tool, but can have a try if target is android.
you can find some useful(or not) script snippets at `agent/`.

## if you wanna have a try after clone

run `npm install` both at easy-frida/ and easy-frida/agent/  
run `npm install -g` at easy-frida/  

open easy-frida/agent/node_modules/frida-compile/index.js,  
find function makeCompiler, add process.cwd() to browserify's options:  

    function makeCompiler(entrypoint, cache, options) {
      const inputs = new Set([ entrypoint ]);
    
      const b = browserify(entrypoint, {
        basedir: process.cwd(),
        extensions: ['.js', '.json', '.cy', '.ts'],
        paths: [
          path.dirname(path.dirname(path.dirname(require.resolve('@babel/runtime-corejs2/package.json')))),
          process.cwd(), // add process.cwd() here
        ],

this is for enable config easy-frida/agent/tsconfig.json, to make import path right both in vscode & frida-compile, when our main.ts/main.js can't use relative path, as it is copied from other path to agent/ .

put frida-server at /data/local/tmp/adirf, and chmod it,  
or edit this.serverDir & this.server hardcoded in index.js  

for use of avoidConflict in android.js,  modify & removeModify in index.js:  

inject frida-gadget to android's systemlib by lief (I'm using libqti_performance.so)  
(this systemlib must not load by zygote but do load by every real app  
or zygote will crash on reading tmpdir when selinux is enabled.)  
config frida-gadget to ScriptDirectory /data/local/tmp/fscripts/  
or edit scriptDir hardcoded in index.js at function modify & removeModify  