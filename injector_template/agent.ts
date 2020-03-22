
import * as easy_frida from 'easy_frida';

// for access js modules from interact env
Object.defineProperty(global, "jsm", {
    value: new Proxy({}, {
        has: (target, prop: string) => {
            try { require(prop); return true; } catch { return false; }
        },
        get: (target, prop: string) => {
            try { return require(prop); } catch { return undefined; }
        },
    })
})

console.log('injected');
