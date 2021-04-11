# easy-frida
a tool for easily develop frida agent script/module when reversing  

# feature  

* repl console with auto complete (double click tab)  

![repl](repl.jpg)

* custom command  

![definecmd](definecmd.jpg)

* play with local variables in function  

![interact](interact.jpg)

* many commonly used agent lib functions in fridalib  

# usage  

## install  

    $ git clone https://github.com/tacesrever/easy-frida.git
    $ cd easy-frida/
    $ npm install
    $ npm link
    $ cd agent/dist/
    $ npm install
    $ npm link

## use  

run`create-injector` at empty directory (see `scripts/create-injector.js`)  

edit target in injector.js  

run injector.js with node  