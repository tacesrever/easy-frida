## gadget-loader  

when I inject frida-gadget.so into zygote for persistent modification, there will be problems:

* zygote will crash with selinux enabled when ScriptDirectory isn't allowed to read by zygote.  
* frida-gadget.so's init function won't be called when app start by zygote's fork.  

so here is an android lib(arm/aarch64 only) which can be injected into zygote for auto load frida-gadget.so when a app started.  

It will:  

* read .config files in ScriptDirectory to determine if current app should load frida-gadget.so.  
* call dlopen("frida-gadget.so") at appropriate time after zygote's fork.  

### usage  

> [中文版](https://bbs.pediy.com/thread-266785.htm)  

Make sure you read [this doc](https://frida.re/docs/gadget/)  

download and put frida-gadget.so on your device, if you have problem with load it, try put them at `/system/lib(64)/*.so` ( [linker-namespace](https://source.android.com/devices/architecture/vndk/linker-namespace) ), or just close selinux.  

config gadget to use ScriptDirectory, and edit LIB_FRIDA and FRIDA_SCRIPT_DIR in gadget-loader.h to suit your paths.  

compile gadget-loader.cpp by ide or ndk.  

inject it into zygote by lief, example:  

```python
import lief
bin = lief.parse("libart.so") # one from /proc/zygote's pid/maps, make sure you have backup
bin.add_library("gadget-loader.so")
bin.write("libart.so")
```

then you can just put your frida script in ScriptDirectory on your device after make some modify to an app.  

