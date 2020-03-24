
import { GetCompletionsAtPositionOptions } from 'typescript';
import * as tslib from 'typescript/lib/tsserverlibrary';
import * as fs from 'fs';
import {JavaLoader, JavaClass, JavaMethod, JavaField} from './javaloader';

const logfile = "D:/pluginlog.txt";

function log(...msg: (string | {toString: () => string})[]) {
    fs.appendFileSync(logfile, msg.map(s => {
        if(s === undefined) return 'undefined';
        if(s === null) return null;
        return s.toString();
    }).join(' ') + "\n");
}

function init(mod: { typescript: typeof tslib }) {
    const typescript = mod.typescript;
    function create(info: tslib.server.PluginCreateInfo) {
        const tsLS = info.languageService;
        let javaLoader;
        try {
            javaLoader = new JavaLoader(info.config.classPaths);
        }
        catch(e) {
            log(e.stack);
        }
        const proxy: tslib.LanguageService = Object.create(null);
        for (let k of Object.keys(info.languageService) as Array<keyof tslib.LanguageService>) {
            const x = info.languageService[k];
            proxy[k] = (...args: Array<{}>) => x.apply(info.languageService, args);
        }
        log("plugin loaded");
        
        function findLastWriteRef(fileName: string, position: number) {
            const refinfos = tsLS.findReferences(fileName, position);
            if(refinfos === undefined) return undefined;
            let reference : tslib.ReferenceEntry = null;
            let definition : tslib.ReferencedSymbolDefinitionInfo = null;

            for (const refinfo of refinfos) {
                for (const ref of refinfo.references) {
                    if(ref.isWriteAccess) {
                        if(reference === null) {
                            reference = ref;
                            definition = refinfo.definition;
                            continue;
                        }

                        if(ref.fileName === fileName) {
                            if(reference.fileName !== ref.fileName) {
                                reference = ref;
                                definition = refinfo.definition;
                            } else if(ref.textSpan.start > reference.textSpan.start) {
                                reference = ref;
                                definition = refinfo.definition;
                            }
                        }
                    }
                }
            }
            return {reference, definition};
        }

        function getSourceFile(fileName: string) {
            return (tsLS as any).getNonBoundSourceFile(fileName) as tslib.SourceFile;
        }

        function getNodeAtPosition(source: tslib.SourceFile, position: number) {
            let current: tslib.Node = source;
            outer: while (true) {
                for (const child of current.getChildren(source)) {
                    const start = child.getFullStart();
                    if (start > position) {
                        break;
                    }
                    
                    const end = child.getEnd();
                    if (position <= end) {
                        current = child;
                        continue outer;
                    }
                }
                return current;
            }
        }

        function getStringLiteral(source: tslib.SourceFile, node: tslib.Node) {
            let current = node;
            while (true) {
                switch(current.kind) {
                    case tslib.SyntaxKind.StringLiteral:
                        return (current as tslib.StringLiteral).text;
                    case tslib.SyntaxKind.Identifier:
                        const writeRef = findLastWriteRef(source.fileName, current.getStart());
                        const writeExpr = getNodeAtPosition(source, writeRef.reference.textSpan.start).parent;
                        current = writeExpr.getChildAt(2);
                        break;
                    default:
                        return undefined;
                }
            }
        }

        function getParentNode(source: tslib.SourceFile, node: tslib.Node, kind: tslib.SyntaxKind) {
            let curNode = node;
            while(curNode.kind !== kind) {
                curNode = curNode.parent;
                if(curNode === source) return undefined;
            }
            return curNode;
        }

        function findClassForExprNode(source: tslib.SourceFile, node: tslib.Node)
            : JavaClass | JavaField | JavaMethod {
            log('find class name for', node.getText());
            let current = node;
            while (true) {
                switch(current.kind) {
                    case tslib.SyntaxKind.CallExpression:
                        let callExpr = current as tslib.CallExpression;
                        let funcExpr = callExpr.expression;
                        let funcName = funcExpr.getText();
                        if(funcName === 'Java.use') {
                            return javaLoader.getClass(getStringLiteral(source, callExpr.arguments[0]));
                        }
                        if(funcName === 'Java.cast') {
                            let klassNode = callExpr.arguments[1];
                            if(klassNode === undefined) return undefined;
                            return findClassForExprNode(source, klassNode);
                        }
                        if(funcExpr.kind === tslib.SyntaxKind.PropertyAccessExpression) {
                            let propexpr = (funcExpr as tslib.PropertyAccessExpression);
                            if(propexpr.name.text !== 'overload') {
                                let declareClass = findClassForExprNode(source, propexpr.expression) as JavaClass;
                                if(declareClass === undefined) return undefined;
                                return declareClass.getMethod(propexpr.name.text).getReturnClass();
                            }
                            let mAccExpr = propexpr.expression as tslib.PropertyAccessExpression;
                            let declareClass = findClassForExprNode(source,mAccExpr.expression) as JavaClass;
                            if(declareClass === undefined) return undefined;
                            let argTypes = [];
                            for(let i = 0; i < callExpr.arguments.length; ++i) {
                                let str = getStringLiteral(source, callExpr.arguments[i]);
                                if(str === undefined) return undefined;
                                argTypes.push(str);
                            }
                            log("argtypes:", JSON.stringify(argTypes));
                            return declareClass.getMethod(mAccExpr.name.text).getReturnClass(argTypes);
                        }
                        return undefined;
                    case tslib.SyntaxKind.Identifier:
                        let writeRef = findLastWriteRef(source.fileName, current.getStart());
                        let typeName = writeRef.definition.name.split(':')[1];
                        if(typeName !== undefined) {
                            typeName = typeName.trim();
                            if(typeName !== 'any' && typeName.indexOf('Java.Wrapper') !== 0) {
                                log("type missmatch:", typeName);
                                return undefined;
                            }
                        }
                        let writeExpr = getNodeAtPosition(source, writeRef.reference.textSpan.start).parent;
                        log("pass assign def:", writeExpr.getText(), "name:", writeRef.definition.name);
                        current = writeExpr.getChildAt(2);
                        break;
                    case tslib.SyntaxKind.ElementAccessExpression:
                    case tslib.SyntaxKind.PropertyAccessExpression:
                        let propRef = findLastWriteRef(source.fileName, current.getChildAt(2).getEnd());
                        if(propRef === undefined) {
                            let klass = findClassForExprNode(source, current.getChildAt(0));
                            if(klass === undefined) return undefined;
                            let propName = current.getChildAt(2).getText();
                            return klass.getProp(propName);
                        }
                        let tmpExpr = getNodeAtPosition(source, propRef.reference.textSpan.start).parent;
                        if(tmpExpr.kind === tslib.SyntaxKind.PropertyAssignment) {
                            current = tmpExpr.getChildAt(2);
                            break;
                        }
                        if(tmpExpr.kind === tslib.SyntaxKind.PropertyAccessExpression) {
                            tmpExpr = tmpExpr.parent;
                            if(tmpExpr.kind === tslib.SyntaxKind.BinaryExpression) {
                                current = tmpExpr.getChildAt(2);
                                break;
                            }
                        }
                        return undefined;
                    default:
                        return undefined;
                }
            }
        }

        proxy.getCompletionsAtPosition = (fileName: string, position: number, options: GetCompletionsAtPositionOptions) => {
            const source = getSourceFile(fileName);
            const oret = tsLS.getCompletionsAtPosition(fileName, position, options);
            try {
                if(options.triggerCharacter === '.') {
                    const completeFor = getNodeAtPosition(source, position).parent.getChildAt(0);
                    log('completeFor ' + completeFor.getText());
                    const klass = findClassForExprNode(source, completeFor);
                    if(klass === undefined) return oret;
                    const extEntries = klass.getCompletionEntries();
                    if(extEntries === undefined) return oret;
                    oret.entries = extEntries.concat(oret.entries).filter(entry => {
                        return (entry.kind !== tslib.ScriptElementKind.warning);
                    });
                }
            } catch(e) {
                log(e.stack);
            }
            return oret;
        }
        
        return proxy;
    }

    return { create };
}
  
export = init;