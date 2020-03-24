import * as tslib from "typescript/lib/tsserverlibrary";
import * as java from "java";
import * as fs from "fs";

let loader: JavaLoader;
export class JavaLoader {
    classCache: Map<string, JavaClass> = new Map();
    constructor(classpaths: string[]) {
        classpaths.forEach(path => {
            if(fs.existsSync(path)) {
                const stat = fs.lstatSync(path);
                if(stat.isDirectory()) {
                    try {
                        java.classpath.pushDir(path);
                    } catch(e) {  };
                }
                else if(stat.isFile()) {
                    try {
                        java.classpath.push(path);
                    } catch(e) {  };
                }
            } else {

            }
        });
        loader = this;
    }

    getClass(className: string): JavaClass {
        if(this.classCache[className] === undefined) {
            this.classCache[className] = new JavaClass(className);
        }
        return this.classCache[className];
    }
}

export class JavaClass {
    klass: any;
    methods: Map<string, JavaMethod> = new Map();
    fields: Map<string, JavaField> = new Map();
    cachedEntries: tslib.CompletionEntry[] = undefined;
    constructor(public className: string) {
        this.klass = java.findClassSync(className);
        let currentClass = this.klass;
        while(currentClass) {
            const tmethods = currentClass.getDeclaredMethodsSync();
            tmethods.forEach(method => {
                const methodName: string = method.getNameSync();
                if(this.methods.get(methodName) === undefined) {
                    this.methods.set(methodName, new JavaMethod(methodName));
                }
                this.methods.get(methodName).addOverload(method);
            });
            const tfields = currentClass.getDeclaredFieldsSync();
            tfields.forEach(field => {
                const fieldName: string = field.getNameSync();
                if(this.fields.get(fieldName) === undefined) {
                    this.fields.set(fieldName, new JavaField(field));
                }
            });
            currentClass = currentClass.getSuperclassSync();
        }
    }

    getProp(name: string) {
        if(this.methods.get(name)) return this.methods.get(name);
        return this.fields.get(name);
    }

    getField(fieldName: string) {
        return this.fields.get(fieldName);
    }

    getMethod(methodName: string) {
        return this.methods.get(methodName);
    }

    getCompletionDetail() {
    }

    getCompletionSymbol() {
    }

    getCompletionEntries() {
        if(this.cachedEntries !== undefined) return this.cachedEntries;
        this.cachedEntries = [];
        let usedNames = [];
        this.methods.forEach((method, name) => {
            let entry: tslib.CompletionEntry = {
                name: name,
                sortText: name,
                kind: tslib.ScriptElementKind.memberFunctionElement,
                source: "Java_c:" + this.className
            };
            this.cachedEntries.push(entry);
        });

        this.fields.forEach((field, name) => {
            let entry: tslib.CompletionEntry = {
                sortText: name,
                name: name,
                source: "Java_c:" + this.className,
                kind: tslib.ScriptElementKind.memberVariableElement
            };
            while(usedNames.includes(name)) name = '_' + name;
            usedNames.push(name);
            entry.name = name;
            this.cachedEntries.push(entry);
        });
        return this.cachedEntries;
    }
}

export class JavaMethod {
    methods: any[] = [];
    argTypes: string[][] = [];
    cachedEntries: tslib.CompletionEntry[] = undefined;
    constructor(public methodName: string) {
    }

    addOverload(method) {
        this.methods.push(method);
    }

    getProp(name: string) {
        return undefined;
    }

    getReturnClass(argTypes?: string[]) {
        if(argTypes === undefined) 
            return loader.getClass(this.methods[0].getReturnTypeSync().getNameSync());
        if(this.argTypes.length === 0) {
            this.getCompletionEntries();
        }
        let midx = 0;
        for(const types of this.argTypes) {
            if(argTypes.length === types.length) {
                let hit = true;
                for(let i = 0; i < types.length; ++i) {
                    if(types[i] !== argTypes[i]) hit = false;
                }
                if(hit) return loader.getClass(this.methods[midx].getReturnTypeSync().getNameSync());
            }
            midx++;
        }
        return undefined;
    }

    getCompletionDetail() {
    }

    getCompletionSymbol() {
    }

    getCompletionEntries() {
        if(this.cachedEntries !== undefined) return this.cachedEntries;
        this.cachedEntries = [];
        const parentClassName = this.methods[0].getDeclaringClassSync().getNameSync();
        this.cachedEntries.push({
            sortText: "methodName",
            name: "methodName",
            source: "Java_m:" + parentClassName,
            kind: tslib.ScriptElementKind.memberVariableElement
        });
        this.cachedEntries.push({
            sortText: "implementation",
            name: "implementation",
            source: "Java_m:" + parentClassName,
            kind: tslib.ScriptElementKind.memberVariableElement
        });
        this.cachedEntries.push({
            sortText: "overloads",
            name: "overloads",
            source: "Java_m:" + parentClassName,
            kind: tslib.ScriptElementKind.memberVariableElement
        });
        this.cachedEntries.push({
            sortText: "argumentTypes",
            name: "argumentTypes",
            source: "Java_m:" + parentClassName,
            kind: tslib.ScriptElementKind.memberVariableElement
        });
        this.cachedEntries.push({
            sortText: "returnType",
            name: "returnType",
            source: "Java_m:" + parentClassName,
            kind: tslib.ScriptElementKind.memberVariableElement
        });

        this.methods.forEach( m => {
            const argTypes: string[] = m.getParameterTypesSync().map(typeclz => {
                return typeclz.getNameSync();
            });
            this.argTypes.push(argTypes);
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
                source: "Java_m:" + this.methods[0].getDeclaringClassSync().getNameSync(),
                kind: tslib.ScriptElementKind.memberVariableElement
            });
        });
        return this.cachedEntries;
    }
}

const fieldCompletionEntries : tslib.CompletionEntry[] = [{
        sortText: "value",
        name: "value",
        kind: tslib.ScriptElementKind.memberVariableElement
    }, {
        sortText: "fieldType",
        name: "fieldType",
        kind: tslib.ScriptElementKind.memberVariableElement
    }, {
        sortText: "fieldReturnType",
        name: "fieldReturnType",
        kind: tslib.ScriptElementKind.memberVariableElement
    }, {
        sortText: "holder",
        name: "holder",
        kind: tslib.ScriptElementKind.memberVariableElement
    },
]
export class JavaField {
    cachedEntries: tslib.CompletionEntry[] = undefined;
    constructor(private field) {
    }

    getCompletionDetail() {
    }

    getCompletionSymbol() {
    }

    getProp(name: string) {
        if(name === 'value') {
            return loader.getClass(this.field.getTypeSync().getNameSync());
        }
        if(name === 'holder') {
            return loader.getClass(this.field.getDeclaringClassSync().getNameSync());
        }
        return undefined;
    }

    getCompletionEntries() {
        if(this.cachedEntries === undefined) {
            this.cachedEntries = fieldCompletionEntries.map(entry => {
                entry.source = "Java_f:" + this.field.getDeclaringClassSync().getNameSync();
                return entry;
            });
        }
        return this.cachedEntries;
    }
}