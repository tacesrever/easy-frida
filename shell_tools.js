
const util = require('util');
const process = require('process');
const child_process = require('child_process');
const execAsync = util.promisify(child_process.exec);

async function exec(command, silence = 0) {
    if(!silence) console.log(command);
    return execAsync(command);
}

exports.adb_shell = async function(command, silence = 0) {
    const cmd = 'adb shell "' + command + '"';
    return exec(cmd, silence);
}

exports.adb_push = async function(localfile, remotefile, silence = 0) {
    const cmd = 'adb push ' + localfile + ' ' + remotefile;
    return exec(cmd, silence);
}

exports.adb_pull = async function(remotefile, rename='', silence = 0) {
    const cmd = 'adb pull ' + remotefile + ' ' + rename;
    return exec(cmd, silence);
}