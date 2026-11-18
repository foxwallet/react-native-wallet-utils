#!/usr/bin/env python3
"""Check 64-bit ELF LOAD/RELRO layouts in .so, .aar, .apk, or .aab files."""

import argparse
import json
from pathlib import Path
import re
import struct
import zipfile

PAGE_SIZE = 16384


def inspect_elf(name, data):
    if data[:4] != b"\x7fELF":
        raise ValueError(f"Not an ELF file: {name}")
    if data[4] != 2:
        return None  # Android's 16 KB requirement applies to 64-bit ABIs.
    endian = "<" if data[5] == 1 else ">"
    header = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
    segments = []
    ndk = []
    for index in range(header[9]):
        values = struct.unpack_from(
            endian + "IIQQQQQQ", data, header[4] + index * header[8]
        )
        kind, flags, offset, address, _, filesz, memsz, alignment = values
        segments.append({
            "type": kind, "flags": flags, "offset": offset,
            "address": address, "filesz": filesz, "memsz": memsz,
            "alignment": alignment,
        })
        if kind == 4:  # PT_NOTE
            cursor = offset
            while cursor + 12 <= offset + filesz:
                namesz, descsz, note_type = struct.unpack_from(endian + "III", data, cursor)
                cursor += 12
                owner = data[cursor:cursor + namesz].rstrip(b"\0")
                cursor += (namesz + 3) & ~3
                description = data[cursor:cursor + descsz]
                cursor += (descsz + 3) & ~3
                if owner == b"Android" and note_type == 1 and descsz >= 132:
                    ndk.append(description[4:68].split(b"\0")[0].decode())

    loads = [segment for segment in segments if segment["type"] == 1]
    errors = []
    if not loads or any(
        segment["alignment"] < PAGE_SIZE
        or (segment["address"] - segment["offset"]) % PAGE_SIZE
        for segment in loads
    ):
        errors.append("LOAD alignment or address/offset congruence is below 16 KB")
    for relro in (segment for segment in segments if segment["type"] == 0x6474E552):
        end = relro["address"] + relro["memsz"]
        protection_end = (end + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE
        if any(
            segment["flags"] & 2
            and max(end, segment["address"])
            < min(protection_end, segment["address"] + segment["memsz"])
            for segment in loads
        ):
            errors.append("RELRO page protection overlaps subsequent writable LOAD data")
    return {"path": name, "ndk": ndk, "errors": errors}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", type=Path, nargs="+")
    parser.add_argument("--min-ndk", type=int, help="Also reject older Android NDK notes")
    parser.add_argument("--json", action="store_true", help="Print the full results as JSON")
    args = parser.parse_args()
    results = []
    for artifact in args.artifacts:
        if zipfile.is_zipfile(artifact):
            with zipfile.ZipFile(artifact) as archive:
                for name in archive.namelist():
                    if name.endswith(".so"):
                        row = inspect_elf(f"{artifact}:{name}", archive.read(name))
                        if row:
                            results.append(row)
        else:
            row = inspect_elf(str(artifact), artifact.read_bytes())
            if row:
                results.append(row)
    if not results:
        parser.error("No 64-bit ELF shared libraries found")
    if args.min_ndk:
        for row in results:
            versions = [re.match(r"r(\d+)", version) for version in row["ndk"]]
            if not versions or any(not version or int(version[1]) < args.min_ndk for version in versions):
                row["errors"].append(f"NDK note missing or older than r{args.min_ndk}")
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for row in results:
            status = "FAIL" if row["errors"] else "PASS"
            print(f"{status} {row['path']} NDK={','.join(row['ndk']) or 'unknown'}")
            for error in row["errors"]:
                print(f"  {error}")
        print(f"Checked {len(results)} 64-bit libraries; {sum(bool(row['errors']) for row in results)} failures")
    raise SystemExit(int(any(row["errors"] for row in results)))


if __name__ == "__main__":
    main()
