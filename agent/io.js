
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