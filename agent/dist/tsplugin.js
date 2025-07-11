"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.enable = enable;
// https://github.com/tacesrever/frida-tsplugin
const http = __importStar(require("http"));
const url = __importStar(require("url"));
const qs = __importStar(require("querystring"));
const frida_java_bridge_1 = __importDefault(require("frida-java-bridge"));
const routeMap = {};
let wrapperProps = [];
function enable(listenPort = 28042) {
    const server = http.createServer(function (req, res) {
        const uri = url.parse(req.url);
        const handler = routeMap[uri.pathname];
        if (handler) {
            handler(req, res);
        }
        else {
            res.writeHead(404);
            res.write("404 not found");
            res.end();
        }
    });
    if (frida_java_bridge_1.default.available) {
        frida_java_bridge_1.default.perform(() => {
            const JavaString = frida_java_bridge_1.default.use("java.lang.String");
            let prototype = JavaString.__proto__;
            while (prototype.__proto__ !== null) {
                wrapperProps = wrapperProps.concat(Object.getOwnPropertyNames(prototype));
                prototype = prototype.__proto__;
            }
        });
        server.listen(listenPort);
    }
}
routeMap["/getJavaClassInfo"] = function (req, res) {
    const uri = url.parse(req.url);
    const query = qs.parse(uri.query);
    frida_java_bridge_1.default.perform(() => {
        let wrapper;
        try {
            wrapper = frida_java_bridge_1.default.use(query.className);
        }
        catch {
            res.writeHead(404);
            res.end();
            return;
        }
        try {
            const classInfo = {
                alltypes: [],
                fields: {},
                methods: {},
                wrapperProps: wrapperProps
            };
            Object.getOwnPropertyNames(wrapper).forEach(propname => {
                const prop = wrapper[propname];
                if (prop === undefined)
                    return;
                if (prop.fieldReturnType !== undefined) {
                    classInfo.fields[propname] = prop.fieldReturnType.className;
                }
                else {
                    classInfo.methods[propname] = [];
                    prop.overloads.forEach(m => {
                        classInfo.methods[propname].push({
                            returnType: m.returnType.className,
                            argumentTypes: m.argumentTypes.map(type => {
                                return type.className;
                            })
                        });
                    });
                }
            });
            let klass = wrapper.class;
            while (klass !== null) {
                classInfo.alltypes.push(klass.getName());
                klass = klass.getSuperclass();
            }
            wrapper.class.getInterfaces().forEach(iface => {
                classInfo.alltypes.push(iface.getName());
            });
            const constructorInfo = [];
            wrapper.class.getConstructors().forEach(method => {
                constructorInfo.push({
                    argumentTypes: method.getParameterTypes().map(type => type.getName()),
                    returnType: classInfo.alltypes[0]
                });
            });
            classInfo.methods["$new"] = constructorInfo;
            res.writeHead(200);
            res.write(JSON.stringify(classInfo));
            res.end();
            return;
        }
        catch (e) {
            console.log(e);
            res.writeHead(500);
            res.end();
        }
    });
};
//# sourceMappingURL=tsplugin.js.map