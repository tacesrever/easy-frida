# easy-frida
a tool for easily develop frida agent script/module when reversing  

# feature  

* repl console with auto complete (double click tab)  

![repl](repl.jpg)

notice: when doing this, your typed code will eval in frida env.  

* custom command  

![definecmd](definecmd.jpg)

* play with local variables in function  

![interact](interact.jpg)

* many commonly used agent lib functions in agent/ (use in code: `import * as xxx from 'fridalib/xxx'`)  

# usage  

## install  

    $ git clone https://github.com/tacesrever/easy-frida.git
    $ cd agent/dist/
    $ pnpm install
    $ pnpm link --global
    $ cd easy-frida/
    $ pnpm install
    $ pnpm link --global

## use  

run`create-injector` at empty directory (see `scripts/create-injector.js`)  

open the directory with vscode (or other ide with typescript support)  

edit target in injector.js  

write your frida code in agent/main.ts  

run injector.js with node  
