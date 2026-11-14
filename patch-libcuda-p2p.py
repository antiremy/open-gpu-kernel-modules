#!/usr/bin/env python3
"""Patch NVIDIA 620.70.06 libcuda so GPUs with different chip IDs can use P2P.

Checked only on an RTX 3090 and RTX 3060 pair. Exits if any signature is missing.
"""

from pathlib import Path
import re
import sys


# Each rewrite is (byte offset in the signature, replacement bytes).
PATCHES = (
    (
        "chip-ID gate A",
        """
        49 8b 84 24 50 0c 00 00  # mov rax, qword ptr [r12 + 0xc50]
        49 8b 95 50 0c 00 00     # mov rdx, qword ptr [r13 + 0xc50]
        48 39 d0                 # cmp rax, rdx
        74 ??                    # je -> jmp
        48 81 fa c8 00 00 00     # cmp rdx, 0xc8
        75 ??                    # jne
        48 3d c0 00 00 00        # cmp rax, 0xc0
        74 ??                    # je
        48 3d c8 00 00 00        # cmp rax, 0xc8
        75 ??                    # jne
        48 81 fa c0 00 00 00     # cmp rdx, 0xc0
        74 ??                    # je
        83 e0 f0                 # and eax, -0x10
        48 3d f0 00 00 00        # cmp rax, 0xf0
        75 ??                    # jne
        83 e2 f0                 # and edx, -0x10
        48 81 fa f0 00 00 00     # cmp rdx, 0xf0
        74 ??                    # je
        """,
        (18, b"\xeb"),
    ),
    (
        "chip-ID gate B",
        """
        49 8b 87 50 0c 00 00  # mov rax, qword ptr [r15 + 0xc50]
        49 8b 96 50 0c 00 00  # mov rdx, qword ptr [r14 + 0xc50]
        48 39 d0              # cmp rax, rdx
        74 ??                 # je -> jmp
        48 3d c0 00 00 00     # cmp rax, 0xc0
        75 ??                 # jne
        48 81 fa c8 00 00 00  # cmp rdx, 0xc8
        74 ??                 # je
        48 81 fa c0 00 00 00  # cmp rdx, 0xc0
        75 ??                 # jne
        48 3d c8 00 00 00     # cmp rax, 0xc8
        74 ??                 # je
        83 e0 f0              # and eax, -0x10
        48 3d f0 00 00 00     # cmp rax, 0xf0
        75 ??                 # jne
        83 e2 f0              # and edx, -0x10
        48 81 fa f0 00 00 00  # cmp rdx, 0xf0
        74 ??                 # je
        """,
        (17, b"\xeb"),
    ),
    (
        "chip-ID gate C",
        """
        48 8b 83 50 0c 00 00     # mov rax, qword ptr [rbx + 0xc50]
        49 8b 94 24 50 0c 00 00  # mov rdx, qword ptr [r12 + 0xc50]
        48 39 d0                 # cmp rax, rdx
        0f 84 ?? ?? ?? ??        # je rel32 -> nop; jmp rel32
        48 81 fa c8 00 00 00     # cmp rdx, 0xc8
        75 ??                    # jne
        48 3d c0 00 00 00        # cmp rax, 0xc0
        0f 84 ?? ?? ?? ??        # je rel32
        48 81 fa c0 00 00 00     # cmp rdx, 0xc0
        75 ??                    # jne
        48 3d c8 00 00 00        # cmp rax, 0xc8
        0f 84 ?? ?? ?? ??        # je rel32
        83 e0 f0                 # and eax, -0x10
        48 3d f0 00 00 00        # cmp rax, 0xf0
        75 ??                    # jne
        83 e2 f0                 # and edx, -0x10
        48 81 fa f0 00 00 00     # cmp rdx, 0xf0
        0f 84 ?? ?? ?? ??        # je rel32
        """,
        (18, b"\x90\xe9"),
    ),
)


if len(sys.argv) != 2:
    raise SystemExit(f"usage: {sys.argv[0]} LIBCUDA")

source = Path(sys.argv[1])
data = bytearray(source.read_bytes())
changes = []

for name, signature, (branch, replacement) in PATCHES:
    tokens = re.sub(r"#.*", "", signature).split()
    pattern = b"".join(
        b"." if token == "??" else re.escape(bytes.fromhex(token))
        for token in tokens
    )
    matches = list(re.finditer(pattern, data, re.DOTALL))
    if len(matches) != 1:
        raise SystemExit(f"error: {name} signature matched {len(matches)} times instead of once")

    offset = matches[0].start() + branch
    data[offset:offset + len(replacement)] = replacement
    changes.append((name, offset, replacement))

with source.open("r+b") as library:
    for _, offset, replacement in changes:
        library.seek(offset)
        library.write(replacement)

for name, offset, _ in changes:
    print(f"applied: {name} at 0x{offset:x}")
