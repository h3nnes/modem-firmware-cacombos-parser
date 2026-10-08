// Minimal ELF32 little-endian reader.
// No external ELF package is required. Works on the whole MBN blob (Uint8Array).
// ParseError message wording is part of the tool's error contract.
import { StructReader, indexOfBytes, utf8 } from "./bytes.js";

export class ParseError extends Error {
  constructor(message) {
    super(message);
    this.name = "ParseError";
  }
}

export class LoadSegment {
  constructor(fileOffset, virtualAddress, fileSize, memorySize) {
    this.fileOffset = fileOffset;
    this.virtualAddress = virtualAddress;
    this.fileSize = fileSize;
    this.memorySize = memorySize;
  }

  containsVaBytes(address, size = 1) {
    return this.virtualAddress <= address && address + size <= this.virtualAddress + this.fileSize;
  }

  containsFileBytes(offset, size = 1) {
    return this.fileOffset <= offset && offset + size <= this.fileOffset + this.fileSize;
  }
}

export class DynamicSymbol {
  constructor(name, value, size, info, fileOffset) {
    this.name = name;
    this.value = value;
    this.size = size;
    this.info = info;
    this.fileOffset = fileOffset;
  }

  get symbolType() {
    return this.info & 0x0f;
  }
}

export class Elf32Image {
  constructor(data) {
    this.data = data;
    this.loadSegments = this.#readLoadSegments();
  }

  #readLoadSegments() {
    const data = this.data;
    if (data.length < 52 || data[0] !== 0x7f || data[1] !== 0x45 || data[2] !== 0x4c || data[3] !== 0x46) {
      throw new ParseError("Input is not an ELF file.");
    }
    if (data[4] !== 1) {
      throw new ParseError("Only ELF32 files are supported.");
    }
    if (data[5] !== 1) {
      throw new ParseError("Only little-endian ELF files are supported.");
    }

    const r = new StructReader(data);
    const programHeaderOffset = r.u32(28);
    const programHeaderSize = r.u16(42);
    const programHeaderCount = r.u16(44);
    if (programHeaderSize < 32) {
      throw new ParseError("ELF program-header entry is unexpectedly small.");
    }

    const tableEnd = programHeaderOffset + programHeaderSize * programHeaderCount;
    if (tableEnd > data.length) {
      throw new ParseError("ELF program-header table extends beyond the file.");
    }

    const segments = [];
    for (let index = 0; index < programHeaderCount; index++) {
      const offset = programHeaderOffset + index * programHeaderSize;
      const [segmentType, fileOffset, virtualAddress, , fileSize, memorySize] = r.unpack("<8I", offset);
      if (segmentType !== 1 || fileSize === 0) continue; // PT_LOAD
      if (fileOffset + fileSize > data.length) {
        throw new ParseError(`ELF load segment ${index} extends beyond the input file.`);
      }
      segments.push(new LoadSegment(fileOffset, virtualAddress, fileSize, memorySize));
    }

    if (segments.length === 0) {
      throw new ParseError("ELF contains no file-backed PT_LOAD segments.");
    }
    return segments;
  }

  vaToOffset(address, size = 1) {
    for (const segment of this.loadSegments) {
      if (segment.containsVaBytes(address, size)) {
        return segment.fileOffset + address - segment.virtualAddress;
      }
    }
    return null;
  }

  offsetToVa(offset, size = 1) {
    for (const segment of this.loadSegments) {
      if (segment.containsFileBytes(offset, size)) {
        return segment.virtualAddress + offset - segment.fileOffset;
      }
    }
    return null;
  }

  // [start, end] pairs per load segment.
  mappedFileRanges() {
    return this.loadSegments.map((segment) => [segment.fileOffset, segment.fileOffset + segment.fileSize]);
  }

  // Reads the SysV dynamic symbol table without section headers; DT_HASH
  // supplies the exact symbol count.
  dynamicSymbols() {
    const data = this.data;
    const r = new StructReader(data);
    const phoff = r.u32(28);
    const phentsize = r.u16(42);
    const phnum = r.u16(44);

    let dynamicFileOffset = null;
    let dynamicFileSize = 0;
    for (let index = 0; index < phnum; index++) {
      const offset = phoff + index * phentsize;
      const [segmentType, fileOffset, , , fileSize] = r.unpack("<8I", offset);
      if (segmentType === 2) { // PT_DYNAMIC
        dynamicFileOffset = fileOffset;
        dynamicFileSize = fileSize;
        break;
      }
    }

    if (dynamicFileOffset === null) return [];

    const tags = new Map();
    const end = dynamicFileOffset + dynamicFileSize;
    for (let offset = dynamicFileOffset; offset < end; offset += 8) {
      const [tag, value] = r.unpack("<II", offset);
      if (tag === 0) break;
      tags.set(tag, value);
    }

    // Required SysV dynamic entries.
    const hashVa = tags.get(4);    // DT_HASH
    const symtabVa = tags.get(6);  // DT_SYMTAB
    const strtabVa = tags.get(5);  // DT_STRTAB
    const syment = tags.has(11) ? tags.get(11) : 16;
    const strsz = tags.has(10) ? tags.get(10) : null;
    if (hashVa === undefined || symtabVa === undefined || strtabVa === undefined) return [];
    if (syment < 16) return [];

    const hashOffset = this.vaToOffset(hashVa, 8);
    const symtabOffset = this.vaToOffset(symtabVa, 16);
    const strtabOffset = this.vaToOffset(strtabVa, 1);
    if (hashOffset === null || symtabOffset === null || strtabOffset === null) return [];

    const [, symbolCount] = r.unpack("<II", hashOffset);
    if (!(1 <= symbolCount && symbolCount <= 1000000)) return [];

    const strtabEnd =
      strsz !== null && strtabOffset + strsz <= data.length ? strtabOffset + strsz : data.length;

    const symbols = [];
    for (let index = 0; index < symbolCount; index++) {
      const offset = symtabOffset + index * syment;
      if (offset + 16 > data.length) break;
      const [nameOffset, value, size, info] = r.unpack("<IIIBBH", offset);
      const stringOffset = strtabOffset + nameOffset;
      let name = "";
      if (strtabOffset <= stringOffset && stringOffset < strtabEnd) {
        const nul = indexOfBytes(data, [0], stringOffset);
        if (nul >= 0 && nul < strtabEnd) {
          name = utf8(data, stringOffset, nul);
        }
      }
      const mappedSize = size > 0 ? size : 1;
      symbols.push(new DynamicSymbol(name, value, size, info, this.vaToOffset(value, mappedSize)));
    }
    return symbols;
  }
}
