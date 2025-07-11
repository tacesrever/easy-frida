"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ELFHeader = ELFHeader;
exports.findElfSegment = findElfSegment;
exports.heapSearch = heapSearch;
exports.dumplib = dumplib;
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
        sheader.nameidx = pointer.readU32(); // 0
        offset += 4;
        sheader.type = pointer.add(offset).readU32(); // 4
        offset += 4;
        sheader.flags = parseInt(readPointer(pointer.add(offset))); // 8
        offset += pointerSize;
        sheader.addrPtr = pointer.add(offset); // 0x10
        sheader.addr = readPointer(pointer.add(offset));
        offset += pointerSize;
        sheader.offsetPtr = pointer.add(offset); // 0x18
        sheader.offset = readPointer(pointer.add(offset));
        offset += pointerSize;
        sheader.size = readPointer(pointer.add(offset)); // 0x20
        offset += pointerSize;
        sheader.link = pointer.add(offset).readU32(); // 0x28
        offset += 4;
        sheader.info = pointer.add(offset).readU32(); // 0x2c
        offset += 4;
        sheader.addralign = readPointer(pointer.add(offset)); // 0x30
        offset += pointerSize;
        sheader.entsize = readPointer(pointer.add(offset)); // 0x38
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
    header.phoff = readPointer(header.phoffPtr);
    offset += pointerSize;
    header.shoffPtr = base.add(offset);
    header.shoff = readPointer(header.shoffPtr);
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
function findElfSegment(moduleOrName, segName) {
    let module;
    if (typeof (moduleOrName) === 'string') {
        module = Process.findModuleByName(moduleOrName);
    }
    else
        module = moduleOrName;
    if (module) {
        const mfile = File.readAllBytes(module.path);
        const base = mfile.unwrap();
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
function heapSearch(pattern) {
    let ranges = Process.enumerateMallocRanges();
    let result = [];
    ranges.forEach(function (range) {
        result = result.concat(Memory.scanSync(range.base, range.size, pattern));
    });
    return result;
}
function dumplib(name, outfile) {
    const lib = Process.findModuleByName(name);
    const libfile = File.readAllBytes(lib.path);
    const filebase = libfile.unwrap();
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
//# sourceMappingURL=linux.js.map