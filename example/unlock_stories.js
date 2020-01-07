
const ef = require('./easy_frida.js');
const na = require('./native.js');
const il2cpp = require('./il2cpp.js');
global.il2cpp = il2cpp;
global.na = na;

il2cpp.perform(function() {
    const HandBookStoryViewModel = il2cpp.fromFullname("Torappu.UI.HandBook.HandBookStoryViewModel");
    const HandBookInfoTextViewModel = il2cpp.fromFullname("Torappu.UI.HandBook.HandBookInfoTextViewModel");
    
    Interceptor.attach(HandBookStoryViewModel.ConvertFromData.ptr, {
        onEnter: function(args) {
            let viewdata = il2cpp.fromObject(args[1]);
            let stories = viewdata.stories;
            let size = stories._size;
            let itemsPtr = stories._items.$handle.add(0x10);
            for(let i = 0; i < size; i++) {
                let storytext = il2cpp.fromObject(itemsPtr.add(4*i).readPointer());
                storytext.unLockType = 0;
            }
        }
    });
    
    Interceptor.attach(HandBookInfoTextViewModel.ConvertFromData.ptr, {
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

