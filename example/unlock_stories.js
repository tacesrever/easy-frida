
const ef = require('./easy_frida.js');
const na = require('./native.js');
const il2cpp = require('./il2cpp.js');
global.il2cpp = il2cpp;
global.na = na;

il2cpp.perform(function() {
    const HandBookStoryViewModel = il2cpp.fromFullname("Torappu.UI.HandBook.HandBookStoryViewModel");
    const HandBookInfoTextViewModel = il2cpp.fromFullname("Torappu.UI.HandBook.HandBookInfoTextViewModel");
    
    Interceptor.attach(HandBookStoryViewModel.$methods.ConvertFromData, {
        onEnter: function(args) {
            let viewdata = il2cpp.fromObject(args[1]);
            let stories = viewdata.stories;
            let size = stories._size;
            let items = stories._items;
            for(let i = 0; i < size; i++) {
                let storytext = il2cpp.fromObject(items.$handle.add(0x10+4*i).readPointer());
                storytext.unLockType = 0;
            }
        }
    });
    
    Interceptor.attach(HandBookInfoTextViewModel.$methods.ConvertFromData, {
        onLeave: function(retVal) {
            let tview = il2cpp.fromObject(retVal);
            tview.unLockorNot = 1;
        }
    });
});

if(ef.isServer) {
    Process.setExceptionHandler(function(details) {
        console.log(JSON.stringify(details));
        var ret = false;
        eval(ef.interact);
        return ret;
    });
}

