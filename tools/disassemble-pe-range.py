"""Disassemble a virtual-address range directly from a 32-bit PE image."""

from __future__ import annotations

import argparse
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_32


def number(value: str) -> int:
    return int(value, 0)


def image_layout(data: bytes) -> tuple[int, list[dict]]:
    if data[:2] != b"MZ":
        raise RuntimeError("Not a PE image")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe : pe + 4] != b"PE\0\0":
        raise RuntimeError("Missing PE signature")
    number_of_sections = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic != 0x10B:
        raise RuntimeError(f"Expected PE32 image, optional-header magic is 0x{magic:X}")
    image_base = struct.unpack_from("<I", data, optional + 28)[0]
    sections = []
    table = optional + optional_size
    for index in range(number_of_sections):
        offset = table + index * 40
        name = data[offset : offset + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
        sections.append(
            {
                "name": name,
                "virtualAddress": virtual_address,
                "virtualSize": virtual_size,
                "rawOffset": raw_offset,
                "rawSize": raw_size,
            }
        )
    return image_base, sections


def virtual_bytes(data: bytes, image_base: int, sections: list[dict], address: int, size: int) -> bytes:
    rva = address - image_base
    for section in sections:
        start = section["virtualAddress"]
        span = max(section["virtualSize"], section["rawSize"])
        if start <= rva < start + span:
            relative = rva - start
            available = max(0, section["rawSize"] - relative)
            raw = data[section["rawOffset"] + relative : section["rawOffset"] + relative + min(size, available)]
            if len(raw) < size:
                raw += bytes(size - len(raw))
            return raw
    raise RuntimeError(f"Virtual address 0x{address:08X} is outside PE sections")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--address", action="append", type=number, required=True)
    parser.add_argument("--size", type=number, default=0x200)
    args = parser.parse_args()
    data = args.image.read_bytes()
    image_base, sections = image_layout(data)
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    for address in args.address:
        code = virtual_bytes(data, image_base, sections, address, args.size)
        print(f"address=0x{address:08X} size=0x{len(code):X} imageBase=0x{image_base:08X}")
        for instruction in disassembler.disasm(code, address):
            encoded = instruction.bytes.hex(" ").ljust(29)
            print(f"  {instruction.address:08X}  {encoded}  {instruction.mnemonic:<9} {instruction.op_str}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
