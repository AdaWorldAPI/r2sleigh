#!/usr/bin/env python3
"""Write the scanned-Go fixtures: Go build information in `.data`, under no section Go names.

A stripped PE keeps its build information in `.data` at a 16-byte boundary, where Go's own
`debug/buildinfo` looks; no `.go.buildinfo`, no pclntab section and no DWARF say Go. These are
the smallest ELFs that say Go only that way: one code section and one data section, one stating
a release (`go_scanned.elf`) and one a development toolchain's version (`go_devel.elf`).
"""

import pathlib
import struct

TEXT = bytes([0xC3] + [0x90] * 15)  # ret
NAMES = b"\0.text\0.data\0.shstrtab\0"


def header(name, kind, flags, addr, off, size, align):
    return struct.pack("<IIQQQQIIQQ", name, kind, flags, addr, off, size, 0, 0, align, 0)


def image(data):
    offset = {name: NAMES.index(b"\0" + name.encode() + b"\0") + 1 for name in (".text", ".data", ".shstrtab")}
    text_off = 0x40
    data_off = text_off + len(TEXT)
    names_off = data_off + len(data)
    shoff = names_off + len(NAMES)
    shoff += -shoff % 8
    sections = b"".join([
        header(0, 0, 0, 0, 0, 0, 0),
        header(offset[".text"], 1, 0x6, 0x401000, text_off, len(TEXT), 16),
        header(offset[".data"], 1, 0x3, 0x402000, data_off, len(data), 16),
        header(offset[".shstrtab"], 3, 0, 0, names_off, len(NAMES), 1),
    ])
    elf = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8)
    elf += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x401000, 0, shoff, 0, 64, 0, 0, 64, 4, 3)
    elf += b"\0" * (text_off - len(elf))
    elf += TEXT + data + NAMES
    elf += b"\0" * (shoff - len(elf))
    return bytes(elf + sections)


def write(name, version):
    # Go 1.18's inline form: the 32-byte header, then the version as a one-byte uvarint and its text.
    info = b"\xff Go buildinf:\x08\x02".ljust(32, b"\0") + bytes([len(version)]) + version
    elf = image(info.ljust(64, b"\0"))
    pathlib.Path(__file__).with_name(name).write_bytes(elf)
    print("wrote", name, len(elf), "bytes")


write("go_scanned.elf", b"go1.21.0")
write("go_devel.elf", b"devel go1.24-abcdef0")
