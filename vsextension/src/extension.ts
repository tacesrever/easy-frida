import * as vscode from 'vscode';

// static auto complete
// trigger by '.'
// is a Java.Warpper? (how to get ts type?)
// 1. get object's classname by static analysis
//      start from Java.use, Java.cast, Java.choose, get it's class info
//      in mid: assign, '.' op, Java.retain, call & ret, pass class info
//      analysis by def and use
// 2. find class info by classname
//      from dex and android.jar or other android IDE's tool
// 3. autocomplete by class and method arg info

// tsserver and typescript-language-features, for type info and def use analysis?
// 
export function activate(context: vscode.ExtensionContext) {
    let androidProvider = vscode.languages.registerCompletionItemProvider('javascript', {
        provideCompletionItems(document: vscode.TextDocument, position: vscode.Position, token: vscode.CancellationToken, context: vscode.CompletionContext) {
            
            return [];
        }
    });
    context.subscriptions.push(androidProvider);
}