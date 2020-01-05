
const ef = require('./easy_frida.js');
const ad = require('./android.js');
const na = require('./native.js');
global.ef = ef;
global.na = na;
global.ad = ad;
 
function testScope() {Java.perform( () => {
    let localvar = Java.use("java.lang.String"); 
    eval(ef.interact);
});}

console.log("attached");
Thread.sleep(1);
console.log("attachedmsg2");
na.modules.c.strlen = ['int', ['string']];
console.log("strlen", na.modules.c.strlen("strlen"));
setTimeout(testScope, 500);