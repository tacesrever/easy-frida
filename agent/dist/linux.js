"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.dumplib = exports.heapSearch = exports.enumerateRanges = exports.findElfSegment = exports.ELFHeader = exports.readFile = void 0;
const native_1 = require("./native");
function readFile(filePath) {
    const open = native_1.importfunc(null, "open", 'int', ['string', 'int']);
    const read = native_1.importfunc(null, "read", 'uint', ['int', 'pointer', 'uint']);
    const lseek = native_1.importfunc(null, "lseek", 'int', ['int', 'int', 'int']);
    const close = native_1.importfunc(null, "close", 'int', ['int']);
    const malloc = native_1.importfunc(null, "malloc", 'pointer', ['uint']);
    const realloc = native_1.importfunc(null, "realloc", 'pointer', ['pointer', 'uint']);
    const fd = open(filePath, 0);
    let size = lseek(fd, 0, 2);
    if (size > 0) {
        const base = malloc(size + 0x10);
        lseek(fd, 0, 0);
        read(fd, base, size);
        close(fd);
        return { base, size };
    }
    const chunkSize = 1024;
    let base = malloc(chunkSize);
    let tsize = read(fd, base, chunkSize);
    let offptr = base;
    while (tsize === chunkSize) {
        size += tsize;
        offptr = base.add(size);
        base = realloc(base, size + chunkSize);
        tsize = read(fd, offptr, chunkSize);
    }
    if (tsize >= 0)
        size += tsize;
    return { base, size };
}
exports.readFile = readFile;
function elfid(base) {
    return {
        magic: base.readByteArray(4),
        class: base.add(4).readU8(),
        endian: base.add(5).readU8(),
        version: base.add(6).readU8(),
        abi: base.add(7).readU8(),
        abiversion: base.add(8).readU8()
    };
}
function ELFHeader(base) {
    const header = {};
    let offset = 0;
    header.id = elfid(base);
    offset += 0x10;
    const pointerSize = header.id.class * 4;
    let readPointer;
    if (pointerSize === Process.pointerSize)
        readPointer = p => p.readPointer();
    else if (pointerSize === 4)
        readPointer = p => ptr(p.readU32());
    else
        readPointer = p => p.readU64();
    function ProgramHeader(pointer) {
        const pheader = {};
        let offset = 0;
        pheader.type = pointer.add(offset).readU32();
        offset += 4;
        if (pointerSize === 8) {
            pheader.flags = pointer.add(offset).readU32();
            offset += 4;
        }
        pheader.offset = readPointer(pointer.add(offset));
        offset += pointerSize;
        pheader.vaddr = readPointer(pointer.add(offset));
        offset += pointerSize;
        pheader.paddr = readPointer(pointer.add(offset));
        offset += pointerSize;
        pheader.filesz = readPointer(pointer.add(offset));
        offset += pointerSize;
        pheader.memsz = readPointer(pointer.add(offset));
        offset += pointerSize;
        if (pointerSize === 4) {
            pheader.flags = pointer.add(offset).readU32();
            offset += 4;
        }
        pheader.align = readPointer(pointer.add(offset));
        return pheader;
    }
    function SectionHeader(pointer) {
        const sheader = {};
        let offset = 0;
        sheader.nameidx = pointer.readU32();
        offset += 4;
        sheader.type = pointer.add(offset).readU32();
        offset += 4;
        sheader.flags = parseInt(readPointer(pointer.add(offset)));
        offset += pointerSize;
        sheader.addrPtr = pointer.add(offset);
        sheader.addr = readPointer(pointer.add(offset));
        offset += pointerSize;
        sheader.offsetPtr = pointer.add(offset);
        sheader.offset = readPointer(pointer.add(offset));
        offset += pointerSize;
        sheader.size = readPointer(pointer.add(offset));
        offset += pointerSize;
        sheader.link = pointer.add(offset).readU32();
        offset += 4;
        sheader.info = pointer.add(offset).readU32();
        offset += 4;
        sheader.addralign = readPointer(pointer.add(offset));
        offset += pointerSize;
        sheader.entsize = readPointer(pointer.add(offset));
        return sheader;
    }
    header.type = base.add(offset).readU16();
    offset += 2;
    header.machine = base.add(offset).readU16();
    offset += 2;
    header.version = base.add(offset).readU32();
    offset += 4;
    header.entry = readPointer(base.add(offset));
    offset += pointerSize;
    header.phoffPtr = base.add(offset);
    header.phoff = readPointer(base.add(offset));
    offset += pointerSize;
    header.shoffPtr = base.add(offset);
    header.shoff = readPointer(base.add(offset));
    offset += pointerSize;
    header.flags = base.add(offset).readU32();
    offset += 4;
    header.ehsize = base.add(offset).readU16();
    offset += 2;
    header.phentsize = base.add(offset).readU16();
    offset += 2;
    header.phnum = base.add(offset).readU16();
    offset += 2;
    header.shentsize = base.add(offset).readU16();
    offset += 2;
    header.shnum = base.add(offset).readU16();
    offset += 2;
    header.shstrndx = base.add(offset).readU16();
    header.ProgramHeader = ProgramHeader;
    header.SectionHeader = SectionHeader;
    return header;
}
exports.ELFHeader = ELFHeader;
function findElfSegment(moduleOrName, segName) {
    let module;
    if (typeof (moduleOrName) === 'string') {
        module = Process.findModuleByName(moduleOrName);
    }
    else
        module = moduleOrName;
    if (module) {
        const mfile = readFile(module.path);
        const base = mfile.base;
        const header = ELFHeader(base);
        const SHTbase = base.add(header.shoff);
        const strSHT = header.SectionHeader(SHTbase.add(header.shstrndx * header.shentsize));
        const segNameTable = base.add(strSHT.offset);
        for (let i = 0; i < header.shnum; ++i) {
            let SHTItem = header.SectionHeader(SHTbase.add(i * header.shentsize));
            let curSegName = segNameTable.add(SHTItem.nameidx).readCString();
            if (curSegName === segName) {
                return { addr: module.base.add(SHTItem.addr), size: parseInt(SHTItem.size) };
            }
        }
        return null;
    }
}
exports.findElfSegment = findElfSegment;
function enumerateRanges() {
    const fopen = native_1.importfunc(null, "fopen", 'pointer', ['string', 'string']);
    const fgets = native_1.importfunc(null, "fgets", 'pointer', ['pointer', 'int', 'pointer']);
    const fclose = native_1.importfunc(null, "fclose", 'int', ['pointer']);
    let mapfile = fopen("/proc/self/maps", "r");
    let buffer = Memory.alloc(2048);
    let r = fgets(buffer, 2048, mapfile);
    let result = [];
    let line = "";
    while (!r.isNull()) {
        line = buffer.readCString();
        let range = {};
        let start = line.indexOf('-');
        let end = line.indexOf(' ');
        range.base = ptr(parseInt(line.slice(0, start), 16));
        range.end = ptr(parseInt(line.slice(start + 1, end), 16));
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
        while (end < line.length && line[end] == " ")
            end++;
        range.name = line.substr(end).trim();
        result.push(range);
        r = fgets(buffer, 2048, mapfile);
    }
    fclose(mapfile);
    return result;
}
exports.enumerateRanges = enumerateRanges;
function heapSearch(pattern) {
    let ranges = enumerateRanges();
    let result = [];
    ranges.forEach(function (range) {
        if (range.name[0] == "[" && range.name.indexOf("alloc") > 0) {
            result = result.concat(Memory.scanSync(range.base, range.size, pattern));
        }
    });
    return result;
}
exports.heapSearch = heapSearch;
function dumplib(name, outfile) {
    const lib = Process.findModuleByName(name);
    const libfile = readFile(lib.path);
    const filebase = libfile.base;
    const membase = Memory.alloc(lib.size + 1024 * 1024);
    Memory.protect(lib.base, lib.size, "rwx");
    Memory.copy(membase, lib.base, lib.size);
    if (membase.readCString(4) !== '\x7fELF')
        Memory.copy(membase, filebase, 0x18);
    const fileHeader = ELFHeader(filebase);
    const memHeader = ELFHeader(membase);
    const SectionHeaderBase = filebase.add(fileHeader.shoff);
    const SectionHeaderEnd = SectionHeaderBase.add(fileHeader.shnum * fileHeader.shentsize);
    const SectionSize = parseInt(SectionHeaderEnd.sub(SectionHeaderBase).toString());
    memHeader.shoffPtr.writePointer(ptr(lib.size));
    const memSectionHeaderBase = membase.add(lib.size);
    Memory.copy(memSectionHeaderBase, SectionHeaderBase, SectionSize);
    const strSection = fileHeader.SectionHeader(SectionHeaderBase.add(fileHeader.shstrndx * fileHeader.shentsize));
    const strtbl = filebase.add(strSection.offset);
    Memory.copy(memSectionHeaderBase.add(SectionSize), strtbl, parseInt(strSection.size));
    const memstrSection = fileHeader.SectionHeader(memSectionHeaderBase.add(fileHeader.shstrndx * fileHeader.shentsize));
    memstrSection.offsetPtr.writePointer(ptr(lib.size + SectionSize));
    const out = new File(outfile, "wb");
    out.write(membase.readByteArray(lib.size + SectionSize + parseInt(strSection.size)));
    out.close();
}
exports.dumplib = dumplib;
//# sourceMappingURL=linux.js.map