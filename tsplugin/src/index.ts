
import { GetCompletionsAtPositionOptions } from 'typescript';
import * as tslib from 'typescript/lib/tsserverlibrary';
import {JavaLoader, JavaClass, JavaMethod, JavaField} from './javaloader';
import {setLogfile, log} from './logger';

function init(mod: { typescript: typeof tslib }) {
    const typescript = mod.typescript;

    function create(info: tslib.server.PluginCreateInfo) {
        const tsLS = info.languageService;
        if(info.config.logfile !== undefined) setLogfile(info.config.logfile);
        const javaLoader = new JavaLoader(info.config.classPaths);
        
        const proxy: tslib.LanguageService = Object.create(null);
        for (let k of Object.keys(info.languageService) as Array<keyof tslib.LanguageService>) {
            const x = info.languageService[k];
            proxy[k] = (...args: Array<{}>) => x.apply(info.languageService, args);
        }

        proxy.getCompletionsAtPosition = (fileName: string, position: number, options: GetCompletionsAtPositionOptions) => {
            const source = getSourceFile(fileName);
            let oret = tsLS.getCompletionsAtPosition(fileName, position, options);
            try {
                const completeFor = getNodeAtPosition(source, position).parent.getChildAt(0);
                log("trigger:", options.triggerCharacter, 'completeFor ' + completeFor.getText());
                const klass = findJavaTypeForExprNode(source, completeFor);
                if(klass === undefined) return oret;
                const entries = klass.getCompletionEntries(oret ? oret.entries : undefined);
                if(entries === undefined) return oret;
                if(oret === undefined) {
                    oret = {
                        entries: entries,
                        isGlobalCompletion: false,
                        isMemberCompletion: true,
                        isNewIdentifierLocation: false
                    }
                } else {
                    oret.entries = entries;
                }
            } catch(e) {
                log(e.stack);
            }
            return oret;
        }
        proxy.getCompletionEntryDetails = (fileName, position, name, options, source, pref) => {
            if(source && source.indexOf("Java_") === 0) {
                const [type, className] = source.substr(5).split(':');
                if(type === 'c') {
                    const klass = javaLoader.getClass(className);
                    const details = klass.getCompletionDetails(name);
                    if(details !== undefined) return details;
                }
            }
            return tsLS.getCompletionEntryDetails(fileName, position, name, options, source, pref);
        }
        proxy.getQuickInfoAtPosition = (fileName, position) => {
            const info = tsLS.getQuickInfoAtPosition(fileName, position);
            const source = getSourceFile(fileName);
            try {
                let getInfoFor = getNodeAtPosition(source, position);
                if(getInfoFor.parent.kind === tslib.SyntaxKind.PropertyAccessExpression
                     && getInfoFor.parent.getChildAt(0) !== getInfoFor) {
                    getInfoFor = getInfoFor.parent;
                }
                const klass = findJavaTypeForExprNode(source, getInfoFor);
                if(klass === undefined) return info;
                if(getInfoFor.parent.kind === tslib.SyntaxKind.CallExpression
                    && getInfoFor.parent.getChildAt(0) === getInfoFor) {
                    const callExpr = getInfoFor.parent as tslib.CallExpression;
                    const argTypes = extractArgTypes(source, callExpr);
                    if(argTypes === undefined) return info;
                    info.displayParts = [{
                        text: (klass as JavaMethod).getJavaWarpper(argTypes).toString(),
                        kind: 'text'
                    }]
                    return info;
                }
                info.displayParts = [{
                    text: klass.getJavaWarpper().toString(),
                    kind: 'text'
                }]
            } catch(e) { log(e.stack); }
            return info;
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
                        return current;
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

        function findJavaTypeForExprNode(source: tslib.SourceFile, node: tslib.Node)
            : JavaClass | JavaField | JavaMethod {
            log('find JavaType for', node.getText());
            let current = node;
            while (true) {
                switch(current.kind) {
                    case tslib.SyntaxKind.CallExpression:
                        return findReturnType(source, current as tslib.CallExpression);
                    
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
                        if(writeRef.definition.kind === tslib.ScriptElementKind.parameterElement) {
                            current = writeExpr;
                            break;
                        }
                        while(writeExpr.kind === tslib.SyntaxKind.PropertyAccessExpression)
                            writeExpr = writeExpr.parent;
                        if(! [
                            tslib.SyntaxKind.BinaryExpression, 
                            tslib.SyntaxKind.PropertyAssignment,
                            tslib.SyntaxKind.VariableDeclaration,
                        ].includes(writeExpr.kind))
                            return undefined;
                        log("pass assign def:", writeExpr.getText());
                        current = writeExpr.getChildAt(2);
                        break;
                    case tslib.SyntaxKind.ElementAccessExpression:
                    case tslib.SyntaxKind.PropertyAccessExpression:
                        let parentNode = current.getChildAt(0);
                        let propNode = current.getChildAt(2);
                        // TODO: some situation like:
                        // class.someStringField.value = "somestr"; class.someStringField.value.?
                        let propWriteRef = undefined;
                        let propName = propNode.getText();
                        if(!["value", "$new", "$init", "overload"].includes(propName))
                            propWriteRef = findLastWriteRef(source.fileName, propNode.getEnd());
                        if(propWriteRef === undefined) {
                            let klass = findJavaTypeForExprNode(source, parentNode);
                            if(klass === undefined) return undefined;
                            return klass.getProp(propNode.getText());
                        }
                        let tmpExpr = getNodeAtPosition(source, propWriteRef.reference.textSpan.start).parent;
                        if(tmpExpr.kind === tslib.SyntaxKind.PropertyAssignment) {
                            current = tmpExpr.getChildAt(2);
                            break;
                        }
                        while(tmpExpr.kind === tslib.SyntaxKind.PropertyAccessExpression)
                            tmpExpr = tmpExpr.parent;
                        if(tmpExpr.kind === tslib.SyntaxKind.BinaryExpression) {
                            current = tmpExpr.getChildAt(2);
                            break;
                        }
                        return undefined;
                    // parse this and params from:
                    // func.impl = (...args)
                    // Java.choose => onMatch: function (instance)
                    case tslib.SyntaxKind.ThisKeyword:
                    case tslib.SyntaxKind.Parameter:
                        let target = current;
                        while(![tslib.SyntaxKind.FunctionExpression,
                                tslib.SyntaxKind.FunctionDeclaration,
                                tslib.SyntaxKind.ArrowFunction]
                                .includes(current.kind))
                            current = current.parent;
                        let funcDefExpr = current as tslib.FunctionLikeDeclaration;
                        let funcAssignExpr: tslib.Node;
                        if(funcDefExpr.name !== undefined) {
                            // TODO: for named function, find use of it
                            return undefined;
                        } else {
                            funcAssignExpr = funcDefExpr.parent;
                        }
                        if(! [
                            tslib.SyntaxKind.BinaryExpression,
                            tslib.SyntaxKind.PropertyAssignment,
                        ].includes(funcAssignExpr.kind))
                            return undefined;
                        // TODO here
                        // this or param
                        // onMatch or impl
                    default:
                        return undefined;
                }
            }
        }

        function findReturnType(source: tslib.SourceFile, callExpr: tslib.CallExpression) {
            let funcExpr = callExpr.expression;
            if(funcExpr.kind === tslib.SyntaxKind.PropertyAccessExpression) {
                let funcPropAccExpr = funcExpr as tslib.PropertyAccessExpression;
                let funcName = funcPropAccExpr.name.text;

                if(funcPropAccExpr.expression.getText() === "Java") {
                    if(funcName === 'use') {
                        return javaLoader.getClass(getStringLiteral(source, callExpr.arguments[0]));
                    }
                    if(funcName === 'cast') {
                        let klassNode = callExpr.arguments[1];
                        if(klassNode === undefined) return undefined;
                        return findJavaTypeForExprNode(source, klassNode);
                    }
                    return undefined;
                }
                let parent = findJavaTypeForExprNode(source, funcPropAccExpr.expression);
                if(parent === undefined) return undefined;
                if(funcName === 'overload') {
                    let method = parent as JavaMethod;
                    let argTypes = extractArgTypes(source, callExpr);
                    if(argTypes === undefined) return undefined;
                    return method.getOverloadMethod(argTypes);
                } else {
                    let klass = parent as JavaClass;
                    let method = klass.getMethod(funcName);
                    if(method.getOverloadCount() === 1)
                        return method.getReturnClass();
                    let argTypes = extractArgTypes(source, callExpr);
                    if(argTypes === undefined) return undefined;
                    return method.getReturnClass(argTypes);
                }
            }
            let javaMethod = findJavaTypeForExprNode(source, funcExpr) as JavaMethod;
            if(javaMethod === undefined) return undefined;
            return javaMethod.getReturnClass();
        }

        function extractArgTypes(source: tslib.SourceFile, callExpr: tslib.CallExpression) {
            let argTypes: string[] = [];
            for(let i = 0; i < callExpr.arguments.length; ++i) {
                let arg = callExpr.arguments[i];
                let typeName = commonTypeToJavaType(source, arg);
                if(typeName === undefined) {
                    let type = findJavaTypeForExprNode(source, arg);
                    if(type === undefined) return undefined;
                    typeName = type.getTypeName();
                }
                argTypes.push(typeName);
            }
            return argTypes;
        }
        
        function commonTypeToJavaType(source: tslib.SourceFile, node: tslib.Node): string {
            switch(node.kind) {
                case tslib.SyntaxKind.NumericLiteral:
                    return 'int';
                case tslib.SyntaxKind.TrueKeyword:
                case tslib.SyntaxKind.FalseKeyword:
                    return 'boolean';
                case tslib.SyntaxKind.NullKeyword:
                case tslib.SyntaxKind.UndefinedKeyword:
                    return null;
                case tslib.SyntaxKind.StringLiteral:
                    return 'java.lang.String';
                case tslib.SyntaxKind.Identifier:
                    let writeRef = findLastWriteRef(source.fileName, node.getStart());
                    if(writeRef === undefined) return undefined;
                    let typeName = writeRef.definition.name.split(':')[1];
                    if(typeName !== undefined) {
                        typeName = typeName.trim();
                        switch(typeName) {
                            case 'number':
                                return 'int';
                            case 'boolean':
                                return 'boolean';
                            case 'string':
                                return 'java.lang.String';
                            default:
                                break;
                        }
                    }
                    let writeExpr = getNodeAtPosition(source, writeRef.reference.textSpan.start).parent;
                    while(writeExpr.kind === tslib.SyntaxKind.PropertyAccessExpression)
                        writeExpr = writeExpr.parent;
                    if(! [
                        tslib.SyntaxKind.BinaryExpression, 
                        tslib.SyntaxKind.PropertyAssignment,
                        tslib.SyntaxKind.VariableDeclaration,
                    ].includes(writeExpr.kind))
                        return undefined;
                    if(typeName !== undefined && typeName.indexOf('Java.Wrapper') === 0)
                        return findJavaTypeForExprNode(source, writeExpr.getChildAt(2)).getTypeName();
                    return commonTypeToJavaType(source, writeExpr.getChildAt(2));
                default:
                    return undefined;
            }
        }
        
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

        function findFirstUseRef(fileName: string, position: number) {
            const refinfos = tsLS.findReferences(fileName, position);
            if(refinfos === undefined) return undefined;
            
            for (const refinfo of refinfos) {
                for (const ref of refinfo.references) {
                    if(ref.isWriteAccess !== true) {
                        return {reference: ref, definition: refinfo.definition};
                    }
                }
            }

            return undefined;
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
        
        log("plugin loaded");
        return proxy;
    }

    return { create };
}
  
export = init;