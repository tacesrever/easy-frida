
global.$ = this;

const ef = require('./easy_frida.js');
const ad = require('./android.js');
this.ad = ad;
this.ef = ef;
 
function testScope() {Java.perform( () => {
    let localvar = Java.use("java.lang.String"); 
    eval(ef.interact);
});}

console.log("attached");
Thread.sleep(1);
console.log("attachedmsg2");
setTimeout(testScope, 500);