
const EasyFrida = require('easy-frida');
const testTarget = 'com.';
async function run() {
    const proc = new EasyFrida(testTarget);
    await proc.watch('example_agent.js');
    proc.interact();
}
run();
