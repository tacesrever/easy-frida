
async function run() {
    const { default:EasyFrida } = await import("easy-frida");

    const proc = new EasyFrida("target", "usb", "android");
    await proc.watch('main.ts');
    proc.interact();
}

run();