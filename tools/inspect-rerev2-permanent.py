"""Read-only verification that the production co-op hooks were installed."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "hud", Path(__file__).with_name("test-rerev2-sp-hud-live.py")
)
hud = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hud)


def relative_target(process, site: int, opcode: int) -> int:
    code = process.read(site, 5)
    if code[0] != opcode:
        raise RuntimeError(f"Expected opcode {opcode:02X} at 0x{site:08X}: {code.hex()}")
    return site + 5 + struct.unpack("<i", code[1:])[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", required=True, type=lambda value: int(value, 0))
    args = parser.parse_args()
    process = hud.Process(args.pid, False)
    try:
        identity = process.identity()
        asi = Path(identity["image"]).parent / "scripts/ResidentEvilRevelations2.FusionFix.asi"
        inventory_update = process.integer(0x139CCEC)
        inventory_base = inventory_update - 69
        expected = {
            0x139CD20: inventory_base + 0x1000,
            0x139CCEC: inventory_base + 69,
            0x139AFD4: inventory_base + 0x2800,
        }
        for address, value in expected.items():
            process.expect(address, struct.pack("<I", value))
        if relative_target(process, 0x8F7A54, 0xE8) != inventory_base + 0x1800:
            raise RuntimeError("Campaign standard preview wrapper was not installed")
        if relative_target(process, 0x8FA310, 0xE8) != inventory_base + 0x2000:
            raise RuntimeError("Campaign alternate preview wrapper was not installed")
        for site in (0x8F79E1, 0x8F7A01, 0x8F7A33, 0x8FA217,
                     0x8FA25E, 0x8FA28F, 0x8FA2BD, 0x8FA2EF):
            process.expect(site, b"\x30\xC0")

        center = struct.unpack("<f", process.read(0x8E2A13, 4))[0]
        if center != 640.0:
            raise RuntimeError(f"CommandFar center is {center}, expected 640")
        far_animation = relative_target(process, 0x8E323F, 0xE8)
        far_draw = process.integer(0x139AB98)
        near_update = process.integer(0x139ACC4)
        far_update = process.integer(0x139AB64)
        for name, value, original in (
            ("farDraw", far_draw, 0xE18040),
            ("nearUpdate", near_update, 0x8E34F0),
            ("farUpdate", far_update, 0x8E29E0),
        ):
            if value == original:
                raise RuntimeError(f"{name} still points to its native entry")

        process.expect(0x98861C, b"\xE9")
        process.expect(0xE6308A, b"\xE9")
        result = {
            "status": "installed",
            "pid": args.pid,
            "created": identity["created"],
            "asiSha256": hashlib.sha256(asi.read_bytes()).hexdigest(),
            "inventoryAllocation": f"0x{inventory_base:08X}",
            "commandFarAnimation": f"0x{far_animation:08X}",
            "farDraw": f"0x{far_draw:08X}",
            "nearUpdate": f"0x{near_update:08X}",
            "farUpdate": f"0x{far_update:08X}",
            "commandFarCenter": center,
            "frida": False,
        }
        print(json.dumps(result, indent=2))
        return 0
    finally:
        process.close()


if __name__ == "__main__":
    raise SystemExit(main())
