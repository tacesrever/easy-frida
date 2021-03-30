"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.setRecvListener = exports.setSendListener = exports.setKeyLog = exports.setSSLKeyListener = exports.getApi = void 0;
const native = __importStar(require("./native"));
let _api = undefined;
function getApi() {
    if (_api === undefined) {
        _api = Object.create({});
        _api.SSL_get_session = native.importfunc(null, "SSL_get_session", 'pointer', ['pointer']);
        _api.SSL_get_client_random = native.importfunc(null, "SSL_get_client_random", 'int', ['pointer', 'pointer', 'pointer']);
        _api.SSL_SESSION_get_id = native.importfunc(null, "SSL_SESSION_get_id", 'pointer', ['pointer', 'pointer']);
        _api.SSL_SESSION_get_master_key = native.importfunc(null, "SSL_SESSION_get_master_key", 'int', ['pointer', 'pointer', 'int']);
        _api.i2d_SSL_SESSION = native.importfunc(null, "i2d_SSL_SESSION", 'int', ['pointer', 'pointer']);
    }
    return _api;
}
exports.getApi = getApi;
function setSSLKeyListener(listener) {
    const api = getApi();
    const SSL_connect_addr = Module.findExportByName(null, "SSL_connect");
    Interceptor.attach(SSL_connect_addr, {
        onEnter: function (args) {
            this.ssl = args[0];
        },
        onLeave: function (retVal) {
            const session = api.SSL_get_session(this.ssl);
            const p_id = Memory.alloc(128);
            const p_key = Memory.alloc(256);
            const idlen = api.SSL_get_client_random(this.ssl, p_id, 128);
            const keylen = api.SSL_SESSION_get_master_key(session, p_key, 256);
            listener(p_id.readByteArray(idlen), p_key.readByteArray(keylen));
        }
    });
}
exports.setSSLKeyListener = setSSLKeyListener;
function buf2hex(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16).toUpperCase()).slice(-2)).join('');
}
function setKeyLog(filePath) {
    const loged = [];
    setSSLKeyListener(async (id, key) => {
        if (id.byteLength === 0) {
            return;
        }
        const hexid = buf2hex(id);
        if (loged.includes(hexid))
            return;
        loged.push(hexid);
        const logfile = new File(filePath, "a+");
        logfile.write(`RSA ${buf2hex(id)} ${buf2hex(key)}\n`);
        logfile.close();
    });
}
exports.setKeyLog = setKeyLog;
function setSendListener(listener) {
    Interceptor.attach(Module.findExportByName(null, "SSL_write"), {
        onEnter: function (args) {
            listener(args[1], parseInt(args[2].toString()));
        }
    });
}
exports.setSendListener = setSendListener;
function setRecvListener(listener) {
    Interceptor.attach(Module.findExportByName(null, "SSL_read"), {
        onEnter: function (args) {
            this.buf = ptr(args[1]);
        },
        onLeave: function (retVal) {
            listener(this.buf, retVal.toInt32());
        }
    });
}
exports.setRecvListener = setRecvListener;
//# sourceMappingURL=ssl.js.map