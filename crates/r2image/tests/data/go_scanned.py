#!/usr/bin/env python3
"""Write the scanned-Go fixture: Go build information in `.data`, under no section Go names.

A stripped PE keeps its build information in `.data` at a 16-byte boundary, where Go's own
`debug/buildinfo` looks; no `.go.buildinfo`, no pclntab section and no DWARF say Go. This is
the smallest ELF that says Go only that way: one code section and one data section.
"""

import pathlib
import struct

TEXT = bytes([0xC3] + [0x90] * 15)  # ret
INFO = b"\xff Go buildinf:\x08\x02".ljust(32, b"\0") + b"\x09go1.21.0"
DATA = INFO.ljust(64, b"\0")

names = b"\0.text\0.data\0.shstrtab\0"
offset = {name: names.index(b"\0" + name.encode() + b"\0") + 1 for name in (".text", ".data", ".shstrtab")}

text_off = 0x40
data_off = text_off + len(TEXT)
shstrtab_off = data_off + len(DATA)
shoff = shstrtab_off + len(names)
shoff += -shoff % 8


def header(name, kind, flags, addr, off, size, align):
    return struct.pack("<IIQQQQIIQQ", name, kind, flags, addr, off, size, 0, 0, align, 0)


sections = b"".join([
    header(0, 0, 0, 0, 0, 0, 0),
    header(offset[".text"], 1, 0x6, 0x401000, text_off, len(TEXT), 16),
    header(offset[".data"], 1, 0x3, 0x402000, data_off, len(DATA), 16),
    header(offset[".shstrtab"], 3, 0, 0, shstrtab_off, len(names), 1),
])

elf = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8)
elf += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x401000, 0, shoff, 0, 64, 0, 0, 64, 4, 3)
elf += b"\0" * (text_off - len(elf))
elf += TEXT + DATA + names
elf += b"\0" * (shoff - len(elf))
elf += sections

pathlib.Path(__file__).with_name("go_scanned.elf").write_bytes(bytes(elf))
print("wrote go_scanned.elf", len(elf), "bytes")
