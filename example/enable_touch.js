
const easy_frida = require('./easy_frida.js');
const Il2cpp = require('./il2cpp.js');

Il2cpp.perform(function() {
    const GalTouchModule = Il2cpp.fromFullname("MoleMole.GalTouchModule");
    Interceptor.attach(GalTouchModule.get_IsGalTouchHeXie.ptr, {
        onEnter: function(args) {
            let touchModule = Il2cpp.fromObject(args[0]);
            touchModule._canGalTouch = 1;
        }
    });
});