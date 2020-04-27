
import * as easy_frida from 'easy_frida';

if(easy_frida.isServer) console.log('injected');

setImmediate(() => {
    eval(easy_frida.interact);
});
