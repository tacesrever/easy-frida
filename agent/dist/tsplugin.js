// https://github.com/tacesrever/frida-tsplugin
import * as http from 'http';
import * as url from 'url';
import * as qs from 'querystring';
const routeMap = {};
let wrapperProps = [];
export function enable(listenPort = 28042) {
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
    if (Java.available) {
        Java.perform(() => {
            const JavaString = Java.use("java.lang.String");
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
    Java.perform(() => {
        let wrapper;
        try {
            wrapper = Java.use(query.className);
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