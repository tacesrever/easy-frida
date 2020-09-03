
const fs = require('fs');
const path = require('path');
const process = require('process');
const child_process = require('child_process');

const outputdir = process.cwd();
const agentdir = path.join(outputdir, "agent");
const templatedir = path.join(__dirname, '../injector_template');
const files = [
  "injector.js",
  "agent/tsconfig.json",
  "agent/main.ts"
]
if(!fs.existsSync(agentdir)) fs.mkdirSync(agentdir);
for(const file of files) {
  fs.copyFileSync(path.join(templatedir, file), path.join(outputdir, file));
}
child_process.execSync("npm link fridalib", {cwd: agentdir});