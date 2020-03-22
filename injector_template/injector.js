
const EasyFrida = require('easy-frida');
async function run() {
    const proc = new EasyFrida("${target}");
    await proc.watch('agent.ts');
    proc.interact();
}
run();
