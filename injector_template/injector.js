
const EasyFrida = require('easy-frida').default;

async function run() {
    const proc = new EasyFrida("target", "usb", "android");
    await proc.watch('agent/main.ts');
    proc.interact();
}

run();