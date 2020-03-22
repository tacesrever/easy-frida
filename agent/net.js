
const native = require('./native');

function getSocketName ( socketfd ) {
    let addr = Socket.peerAddress(socketfd);
    if(addr) {
        if('ip' in addr) {
            ip = addr.ip.split(':');
            return ip[ip.length-1]+ '_' + addr.port;
        }
        if('path' in addr) {
            return 'unix_socket-' + addr.path;
        }
    }
    return '';
}
exports.getSocketName = getSocketName;


let hosts = {};
let getaddrinfo_hooked = false;
function hostReplace(arghosts) {
    for(let name in arghosts) {
        hosts[name] = Memory.allocUtf8String(arghosts[name]);
    }
    if(getaddrinfo_hooked === false) {
        native.modules.c.getaddrinfo = {
            onEnter: function(args) {
                let hostname = args[0].readCString();
                for(let name in hosts) {
                    if(hostname.indexOf(name) >= 0) {
                        console.log("getaddrinfo replaced:", hostname, name);
                        args[0] = hosts[name];
                        break;
                    }
                }
            }
        }
        getaddrinfo_hooked = true;
    }
}

module.exports = {
    getSocketName,
    hostReplace,
}