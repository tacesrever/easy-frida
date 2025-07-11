
async function run() {
    const { default:EasyFrida } = await import("easy-frida");

    const proc = new EasyFrida("target", "usb", "android");
    proc.watch('main.ts');
    proc.interact();
}

run();