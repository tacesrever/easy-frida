# easy-frida
a simple tool for easyily dev/debug using frida and write module for agent. (mainly used for android)

# Notice
in dev, not a clone-then-use tool, but can have a try if target is android.
you can find some useful(or not) script snippets at `agent/`.

## if you wanna have a try after clone

run `npm install` both at easy-frida/ and easy-frida/agent/  

put frida-server at /data/local/tmp/adirf, and chmod it,  
or edit this.serverDir & this.server hardcoded in index.js  

for use of avoidConflict in android.js,  modify & removeModify in index.js:  

inject frida-gadget to android's systemlib by lief (I'm using libqti_performance.so)  
(this systemlib must not load by zygote but do load by every real app  
or zygote will crash on reading tmpdir.)  
config frida-gadget to ScriptDirectory /data/local/tmp/fscripts/  
or edit scriptDir hardcoded in index.js at function modify & removeModify  

for use of android.libraryOnLoad in android.js:  
pull /system/bin/linker & /system/bin/linker64,  
find __dl__ZN6soinfo17call_constructorsEv's address (using ida etc.)  
edit hardcoded addresses in android.js at function libraryOnLoad.  