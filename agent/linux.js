const native = require('./native');

function findElfSegment(moduleOrName, segName) {
  let module = moduleOrName;
  if(typeof(moduleOrName) === 'string') {
    module = Process.findModuleByName(moduleOrName);
  }
  if(module) {
    let SHT_offset;
    let SHT_size_offset;
    let SHT_count_offset;
    let SHT_strtidx_offset;
    let SHTH_addr_offset;
    let SHTH_vaddr_offset;
    let SHTH_nameidx_offset = 0;
    let SHTH_size_offset;
    if(Process.arch === "arm" || Process.arch === "ia32" ) {
      SHT_offset = 0x20;
      SHT_size_offset = 0x2e;
      SHT_count_offset = 0x30;
      SHT_strtidx_offset = 0x32;
      
      SHTH_vaddr_offset = 0x0c;
      SHTH_addr_offset = 0x10;
      SHTH_size_offset = 0x14;
    } else if (Process.arch === "arm64" || Process.arch === "x64") {
      SHT_offset = 0x28;
      SHT_size_offset = 0x3a;
      SHT_count_offset = 0x3c;
      SHT_strtidx_offset = 0x3e;
      
      SHTH_vaddr_offset = 0x10;
      SHTH_addr_offset = 0x18;
      SHTH_size_offset = 0x20;
    }
    // const elf = new File(module.path, 'rb');
    native.modules.c.fopen.signature = ['pointer', ['string', 'string']];
    native.modules.c.fseek.signature = ['int', ['pointer', 'int', 'int']];
    native.modules.c.ftell.signature = ['int', ['pointer']];
    native.modules.c.fread.signature = ['uint', ['pointer', 'uint', 'uint', 'pointer']];
    native.modules.c.malloc.signature = ['pointer', ['uint']];
    native.modules.c.free.signature = ['int', ['pointer']];
    native.modules.c.fclose.signature = ['int', ['pointer']];
    
    const fd = native.modules.c.fopen(module.path, 'rb');
    native.modules.c.fseek(fd, 0, 2);
    const fsize = native.modules.c.ftell(fd);
    const buffer = native.modules.c.malloc(fsize + 0x10);
    native.modules.c.fseek(fd, 0, 0);
    native.modules.c.fread(buffer, fsize, 1, fd);
    native.modules.c.fclose(fd);
    
    const SHT = buffer.add(SHT_offset).readPointer();
    const SHT_size = buffer.add(SHT_size_offset).readU16();
    const SHT_count = buffer.add(SHT_count_offset).readU16();
    const SHT_strtidx = buffer.add(SHT_strtidx_offset).readU16();
    const SHT_strtblItem = buffer.add(SHT).add(SHT_strtidx*SHT_size);
    const segNameTable = buffer.add(SHT_strtblItem.add(SHTH_addr_offset).readPointer());
    for(let i = 0; i < SHT_count; ++i) {
      let SHT_item = buffer.add(SHT).add(i*SHT_size);
      let curSegAddr = SHT_item.add(SHTH_vaddr_offset).readPointer();
      let curSegSize = parseInt(SHT_item.add(SHTH_size_offset).readPointer().toString(10));
      let segNamePtr = segNameTable.add(SHT_item.add(SHTH_nameidx_offset).readU16());
      let curSegName = segNamePtr.readCString();
      if(curSegName === segName) {
        native.modules.c.free(buffer);
          return {addr: module.base.add(curSegAddr), size: curSegSize};
      }
    }
    native.modules.c.free(buffer);
    return null;
  }
}
exports.findElfSegment = findElfSegment;

function enumerateRanges() {
  native.modules.c.fopen = ['pointer', ['string', 'string']];
  native.modules.c.fgets = ['pointer', ['pointer', 'int', 'pointer']];
  native.modules.c.fclose = ['int', ['pointer']];
  let mapfile = native.modules.c.fopen("/proc/self/maps", "r");
  let buffer = Memory.alloc(2048);
  let r = native.modules.c.fgets(buffer, 2048, mapfile);
  let result = [];
  let line = "";
  while(!r.isNull()) {
    line = buffer.readCString();
    let range = {};
    let start = line.indexOf('-');
    let end = line.indexOf(' ');
    range.base = ptr(parseInt(line.slice(0, start), 16));
    range.end = ptr(parseInt(line.slice(start+1, end), 16));
    range.size = parseInt(range.end.sub(range.base));
    start = end + 1;
    end = start + 4;
    range.prots = line.slice(start, end);
    start = end + 1;
    end = line.indexOf(' ', start);
    range.fileOffset = parseInt(line.slice(start, end), 16);
    start = line.indexOf(' ', end + 1);
    end = line.indexOf(' ', start + 1);
    range.fileSize = parseInt(line.slice(start, end));
    while(end < line.length && line[end] == " ") end++;
    range.name = line.substr(end).trim();
    result.push(range);
    r = native.modules.c.fgets(buffer, 2048, mapfile);
  }
  native.modules.c.fclose(mapfile);
  return result;
}
exports.enumerateRanges = enumerateRanges;

function heapSearch(pattern) {
  let ranges = enumerateRanges();
  let result = [];
  ranges.forEach(function(range) {
    if(range.name[0] == "[" && range.name.indexOf("alloc") > 0) {
      result = result.concat(Memory.scanSync(range.base, range.size, pattern));
    }
  });
  return result;
}
exports.heapSearch = heapSearch;