import * as tslib from "typescript/lib/tsserverlibrary";
import * as java from "java";
import * as fs from "fs";
import {log} from './logger';

export interface ClassInfoProvider {
    getClassName: () => string;
    getExtendClassNames: () => string[];
    getPropInfoProvider: (name: string) => FieldInfoProvider | MethodInfoProvider;
    getFieldInfoProvider: (name: string) => FieldInfoProvider;
    getMethodInfoProvider: (name: string) => MethodInfoProvider;
    getCompletionDetail: (symbolName: string) => tslib.CompletionEntryDetails;
    getCompletionEntries: (originEntries?: tslib.CompletionEntry[]) => tslib.CompletionEntry[];
    getDeclare: () => string;
}

export interface MethodInfoProvider {
    getClassName: () => string;
    getPropInfoProvider: (name: string) => ClassInfoProvider | MethodInfoProvider;
    hasOverload: () => boolean;
    getOverloadInfoProvider: (argTypes?: string[]) => MethodInfoProvider;
    getReturnClassName: (argTypes?: string[]) => string;
    getReturnInfoProvider: (argTypes?: string[]) => ClassInfoProvider;
    getParamClassNames: () => string[];
    getCompletionDetail: (symbolName: string) => tslib.CompletionEntryDetails;
    getCompletionEntries: (originEntries?: tslib.CompletionEntry[]) => tslib.CompletionEntry[];
    getDeclare: (argTypes?: string[]) => string;
}

export interface FieldInfoProvider {
    getClassName: () => string;
    getPropInfoProvider: (name: string) => ClassInfoProvider;
    getCompletionDetail: (symbolName: string) => tslib.CompletionEntryDetails;
    getCompletionEntries: (originEntries?: tslib.CompletionEntry[]) => tslib.CompletionEntry[];
    getDeclare: () => string;
}

let javaLoader: JavaProviderLoader;
export class JavaProviderLoader {
    classCache: Map<string, JavaClassInfoProvider> = new Map();
    constructor(classpaths: string[]) {
        classpaths.forEach(path => {
            if(fs.existsSync(path)) {
                const stat = fs.lstatSync(path);
                if(stat.isDirectory()) {
                    try {
                        java.classpath.pushDir(path);
                    } catch(e) { log(e.stack) };
                }
                else if(stat.isFile()) {
                    try {
                        java.classpath.push(path);
                    } catch(e) { log(e.stack) };
                }
            } else {
            }
        });
        javaLoader = this;
    }

    getProviderByName(className: string): JavaClassInfoProvider {
        if(this.classCache[className] === undefined) {
            this.classCache[className] = new JavaClassInfoProvider(className);
        }
        return this.classCache[className];
    }
}

let objCLoader: ObjCProviderLoader;
export class ObjCProviderLoader {
    constructor() {

    }
}

export class JavaClassInfoProvider implements ClassInfoProvider {
    klass: any;
    extends: string[] = [];
    methods: Map<string, JavaMethodInfoProvider> = new Map();
    fields: Map<string, JavaFieldInfoProvider> = new Map();
    cachedEntries: tslib.CompletionEntry[] = undefined;
    constructor(public className: string) {
        this.klass = java.findClassSync(className);
        
        this.klass.getInterfacesSync().forEach(i => {
            this.extends.push(i.getNameSync());
        });

        this.methods.set("$new", new JavaMethodInfoProvider("$new"));
        this.methods.set("$init", new JavaMethodInfoProvider("$init"));
        this.klass.getConstructorsSync().forEach(method => {
            this.methods.get("$new").addOverload(method);
            this.methods.get("$init").addOverload(method);
        });
        let currentClass = this.klass;
        while(currentClass) {
            currentClass.getDeclaredMethodsSync().forEach(method => {
                const methodName: string = method.getNameSync();
                if(this.methods.get(methodName) === undefined) {
                    this.methods.set(methodName, new JavaMethodInfoProvider(methodName));
                }
                this.methods.get(methodName).addOverload(method);
            });
            currentClass.getDeclaredFieldsSync().forEach(field => {
                const fieldName: string = field.getNameSync();
                if(this.fields.get(fieldName) === undefined) {
                    this.fields.set(fieldName, new JavaFieldInfoProvider(field));
                }
            });
            this.extends.push(currentClass.getNameSync());
            currentClass = currentClass.getSuperclassSync();
        }
    }

    getClassName() {
        return this.className;
    }

    getExtendClassNames() {
        return this.extends;
    }

    getPropInfoProvider(name: string) {
        if(this.getMethodInfoProvider(name)) return this.getMethodInfoProvider(name);
        return this.getFieldInfoProvider(name);
    }

    getFieldInfoProvider(fieldName: string) {
        while(fieldName[0] === '_' && this.fields.get(fieldName) === undefined)
            fieldName = fieldName.substr(1);
        return this.fields.get(fieldName);
    }

    getMethodInfoProvider(methodName: string) {
        return this.methods.get(methodName);
    }

    getDeclare() {
        return this.klass.toString();
    }

    getCompletionDetail(name: string) {
        const isMethod = this.methods.has(name);
        if(!isMethod && !this.getFieldInfoProvider(name)) return undefined;
        let details: tslib.CompletionEntryDetails = {
            name: name,
            kind: isMethod? tslib.ScriptElementKind.memberFunctionElement:
                    tslib.ScriptElementKind.memberVariableElement,
            displayParts: [],
            documentation: [],
            kindModifiers: ''
        }
        details.displayParts.push({
            text: '(',
            kind: 'punctuation'
        });
        details.displayParts.push({
            text: isMethod? 'method': 'field',
            kind: 'text'
        });
        details.displayParts.push({
            text: ')',
            kind: 'punctuation'
        });
        details.displayParts.push({
            text: ' ',
            kind: 'space'
        });
        details.displayParts.push({
            text: this.getPropInfoProvider(name).getDeclare(),
            kind: 'text'
        });
        return details;
    }

    getCompletionEntries(originEntries?: tslib.CompletionEntry[]) {
        if(this.cachedEntries !== undefined) return this.cachedEntries;
        this.cachedEntries = [];
        const fridaClassWarpperProps = {
            // declared in @types/frida-gum:
            "$alloc": tslib.ScriptElementKind.memberFunctionElement,
            "class": tslib.ScriptElementKind.memberVariableElement,
            "$className": tslib.ScriptElementKind.memberVariableElement,
            "$super": tslib.ScriptElementKind.memberVariableElement,
            // currently not (or internal):
            "$dispose": tslib.ScriptElementKind.memberFunctionElement,
            "$clone": tslib.ScriptElementKind.memberFunctionElement,
            "$list": tslib.ScriptElementKind.memberFunctionElement,
            "$ownMembers": tslib.ScriptElementKind.memberVariableElement,
            "$s": tslib.ScriptElementKind.memberVariableElement,
            "toJSON": tslib.ScriptElementKind.memberFunctionElement,
            "$isSameObject": tslib.ScriptElementKind.memberFunctionElement,
            "$getCtor": tslib.ScriptElementKind.memberFunctionElement,
            "$borrowClassHandle": tslib.ScriptElementKind.memberFunctionElement,
            "$copyClassHandle": tslib.ScriptElementKind.memberFunctionElement,
            "$has": tslib.ScriptElementKind.memberFunctionElement,
            "$find": tslib.ScriptElementKind.memberFunctionElement
        }
        for(const name in fridaClassWarpperProps) {
            let entry: tslib.CompletionEntry = {
                name: name,
                sortText: name,
                kind: fridaClassWarpperProps[name],
                source: ""
            };
            this.cachedEntries.push(entry);
        }
        let usedNames = [];
        this.methods.forEach((method, name) => {
            if(!usedNames.includes(name)) usedNames.push(name);
            let entry: tslib.CompletionEntry = {
                name: name,
                sortText: name,
                kind: tslib.ScriptElementKind.memberFunctionElement,
                source: "Java_c:" + this.className
            };
            this.cachedEntries.push(entry);
        });

        this.fields.forEach((field, name) => {
            while(usedNames.includes(name)) name = '_' + name;
            usedNames.push(name);
            let entry: tslib.CompletionEntry = {
                sortText: name,
                name: name,
                source: "Java_c:" + this.className,
                kind: tslib.ScriptElementKind.memberVariableElement
            };
            this.cachedEntries.push(entry);
        });
        return this.cachedEntries;
    }
}

export class JavaMethodInfoProvider implements MethodInfoProvider {
    methods: any[] = [];
    argTypes: string[][] = [];
    cachedEntries: tslib.CompletionEntry[] = undefined;
    constructor(public methodName: string) {
    }

    getClassName() {
        return '';
    }

    hasOverload() {
        return this.methods.length > 1;
    }

    addOverload(method) {
        this.methods.push(method);
        const argTypes: string[] = method.getParameterTypesSync().map(typeclz => {
            return typeclz.getNameSync();
        });
        this.argTypes.push(argTypes);
    }

    getPropInfoProvider(name: string) {
        return undefined;
    }

    getJavaWarpper(argTypes?: string[]) {
        if(argTypes === undefined)
            return this.methods[0];
        let midx = 0;
        for(const types of this.argTypes) {
            if(argTypes.length === types.length) {
                let hit = true;
                for(let i = 0; hit && i < types.length; ++i) {
                    if(argTypes[i] !== null && types[i] !== argTypes[i]) {
                        hit = false;
                        let argClass = javaLoader.getProviderByName(argTypes[i]);
                        for(const subType of argClass.getExtendClassNames()) {
                            if(subType === types[i]) {
                                hit = true;
                                break;
                            }
                        }
                    }
                }
                if(hit) return this.methods[midx];
            }
            midx++;
        }
        return undefined;
    }

    getOverloadInfoProvider(argTypes?: string[]) {
        const method = this.getJavaWarpper(argTypes);
        if(method === undefined) return undefined;
        const aMethod = new JavaMethodInfoProvider(this.methodName);
        aMethod.addOverload(method);
        return aMethod;
    }

    getReturnClassName(argTypes?: string[]): string {
        const method = this.getJavaWarpper(argTypes);
        if(method === undefined) return undefined;
        if(method.getReturnTypeSync !== undefined) {
            return method.getReturnTypeSync().getNameSync();
        }
        // is constructor method
        return method.getNameSync();
    }

    getDeclare(argTypes?: string[]) {
        const method = this.getJavaWarpper(argTypes);
        if(method === undefined) return undefined;
        return method.toString();
    }

    getParamClassNames() {
        return this.argTypes[0];
    }

    getReturnInfoProvider(argTypes?: string[]) {
        let className = this.getReturnClassName(argTypes);
        return className? javaLoader.getProviderByName(className): undefined;
    }

    getCompletionDetail(name: string) {
        if(name.indexOf("overload(") !== 0) return undefined;

        let argTypes = undefined;
        if(name.length > 12)
            argTypes = name.slice(10, -2).split("', '");
        let details: tslib.CompletionEntryDetails = {
            name: name,
            kind: tslib.ScriptElementKind.memberFunctionElement,
            displayParts: [],
            documentation: [],
            kindModifiers: ''
        }
        details.displayParts.push({
            text: this.getDeclare(argTypes),
            kind: 'text'
        });
        return details;
    }

    getCompletionEntries(originEntries?: tslib.CompletionEntry[]) {
        if(this.cachedEntries !== undefined) return this.cachedEntries;
        if(this.methods.length === 0) return undefined;
        this.cachedEntries = [];
        const parentClassName = this.methods[0].getDeclaringClassSync().getNameSync();
        const fridaMethodWarpperProps = [
            "overloads",
            "methodName",
            "holder",
            "type",
            "handle",
            "implementation",
            "returnType",
            "argumentTypes",
            "canInvokeWith",
            "clone",
            "invoke"
        ]
        fridaMethodWarpperProps.forEach(fieldName => {
            this.cachedEntries.push({
                sortText: fieldName,
                name: fieldName,
                source: "Java_m:" + parentClassName + '.' + this.methodName,
                kind: tslib.ScriptElementKind.memberVariableElement
            });
        });

        this.argTypes.forEach(argTypes => {
        let overloadArg = '';
            if(argTypes.length > 0) {
                argTypes.forEach(type => {
                    overloadArg += "'" + type + "', "
                });
                overloadArg = overloadArg.slice(0, -2);
            }

            this.cachedEntries.push({
                sortText: "overload(",
                name: "overload(" + overloadArg + ")",
                source: "Java_m:" + parentClassName + '.' + this.methodName,
                kind: tslib.ScriptElementKind.memberVariableElement
            });
        });
        return this.cachedEntries;
    }
}

export class JavaFieldInfoProvider implements FieldInfoProvider {
    cachedEntries: tslib.CompletionEntry[] = undefined;
    constructor(private field) {
    }

    getDeclare() {
        return this.field.toString();
    }

    getClassName() {
        return this.field.getTypeSync().getNameSync();
    }

    getPropInfoProvider(name: string) {
        if(name === 'value') {
            return javaLoader.getProviderByName(this.field.getTypeSync().getNameSync());
        }
        if(name === 'holder') {
            return javaLoader.getProviderByName(this.field.getDeclaringClassSync().getNameSync());
        }
        return undefined;
    }

    getCompletionDetail(name: string) {
        if(name !== 'value' && name !== 'holder') return undefined;
        let details: tslib.CompletionEntryDetails = {
            name: name,
            kind: tslib.ScriptElementKind.memberFunctionElement,
            displayParts: [],
            documentation: [],
            kindModifiers: ''
        }
        if(name === 'value') {
            details.displayParts.push({
                text: this.field.toString(),
                kind: 'text'
            });
        }
        else if(name === 'holder') {
            details.displayParts.push({
                text: this.field.getDeclaringClassSync().toString(),
                kind: 'text'
            });
        }
        return details;
    }

    getCompletionEntries(originEntries?: tslib.CompletionEntry[]) {
        if(this.cachedEntries !== undefined) return this.cachedEntries;
        const fridaFieldWarpperProps = [
            "value",
            "holder",
            "fieldType",
            "fieldReturnType"
        ];
        const parentClassName = this.field.getDeclaringClassSync().getNameSync();
        const fieldName = this.field.getNameSync();
        this.cachedEntries = [];
        fridaFieldWarpperProps.forEach(propName => {
            this.cachedEntries.push({
                sortText: propName,
                name: propName,
                source: "Java_f:" + parentClassName + '.' + fieldName,
                kind: tslib.ScriptElementKind.memberVariableElement
            });
        })
        return this.cachedEntries;
    }
}