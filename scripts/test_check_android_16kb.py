"""Regression cases for 16 KB RELRO page protection."""

import struct
import unittest

from check_android_16kb import PAGE_SIZE, inspect_elf


def elf_with_relro(loads, relro_start, relro_end):
    """Build ELF64 program headers without needing a native compiler."""
    segments = [
        (1, flags, start, start, start, end - start, end - start, PAGE_SIZE)
        for start, end, flags in loads
    ]
    segments.append((
        0x6474E552, 4, relro_start, relro_start, relro_start,
        relro_end - relro_start, relro_end - relro_start, 1,
    ))
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + bytes(9),
        3, 183, 1, 0, 64, 0, 0, 64, 56, len(segments), 0, 0, 0,
    )
    return header + b"".join(
        struct.pack("<IIQQQQQQ", *segment) for segment in segments
    )


class RelroProtectionTests(unittest.TestCase):
    def test_page_rounding(self):
        cases = [
            ("writable prefix", [(0x4000, 0x8000, 6)], 0x6000, 0x8000, True),
            ("empty prefix", [(0x6000, 0x8000, 6)], 0x6000, 0x8000, False),
            (
                "read-only prefix",
                [(0x4000, 0x6000, 4), (0x6000, 0x8000, 6)],
                0x6000, 0x8000, False,
            ),
            (
                "prefix ends at protected page boundary",
                [(0, 0x4000, 6), (0x6000, 0x8000, 6)],
                0x6000, 0x8000, False,
            ),
            ("writable suffix", [(0x4000, 0xC000, 6)], 0x4000, 0x6000, True),
            ("empty suffix", [(0x4000, 0x6000, 6)], 0x4000, 0x6000, False),
            (
                "suffix starts at protected page boundary",
                [(0x4000, 0x6000, 6), (0x8000, 0xC000, 6)],
                0x4000, 0x6000, False,
            ),
            ("aligned RELRO", [(0x4000, 0xC000, 6)], 0x4000, 0x8000, False),
        ]
        for name, loads, start, end, should_fail in cases:
            with self.subTest(name=name):
                result = inspect_elf(name, elf_with_relro(loads, start, end))
                self.assertEqual(bool(result["errors"]), should_fail, result)


if __name__ == "__main__":
    unittest.main()
