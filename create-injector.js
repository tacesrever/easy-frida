
const process = require('process');
const path = require('path');
const fs = require('fs');

if(process.argv.length !== 3) {
  console.log("useage: create-injector target");
  return;
}

const target = process.argv[2];
const outputdir = process.cwd();
const templatedir = path.join(__dirname, 'injector_template');

const config = {
  "compilerOptions": {
    "target": "esnext",
    "lib": ["esnext"],
    "noEmit": true,
    "strict": true,
    "esModuleInterop": true,
    "baseUrl": path.join(__dirname, 'agent')
  }
}
fs.writeFileSync(path.join(outputdir, 'jsconfig.json'), JSON.stringify(config));

let injectorCode = fs.readFileSync(path.join(templatedir, 'injector.js'), {encoding: 'utf-8'});
injectorCode = injectorCode.replace(/\${target}/g, target);
fs.writeFileSync(path.join(outputdir, 'injector.js'), injectorCode);

fs.copyFileSync(path.join(templatedir, 'agent.ts'), path.join(outputdir, 'agent.ts'));