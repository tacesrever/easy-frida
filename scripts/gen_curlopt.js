
const fs = require('fs');

let code = String(fs.readFileSync('curl.h'));
let start = code.indexOf("CINIT(WRITEDATA, OBJECTPOINT, 1)");
let end = code.indexOf("CURLOPT_LASTENTRY");
code = code.slice(start, end);

let i = code.indexOf("CINIT");
data = {};
while(i >= 0) {
    start = code.indexOf("(", i) + 1;
    end = code.indexOf(")", i);
    let optdef = code.slice(start, end).split(",");
    let optname = optdef[0].trim().toLowerCase();
    let opttype = optdef[1].trim();
    let optid = parseInt(optdef[2].trim());
    data[optid] = {type:opttype, name:optname};
    i = code.indexOf("CINIT", end);
}
fs.writeFileSync('curl.json', JSON.stringify(data));