#!/usr/bin/env python3
"""Patch 4.0.306+ x64 vmlinuz so an already-plaintext xz initrd is used as-is.

When the ramdisk starts with XZ magic, jump past IKMF decrypt to the unxz path.
Recompresses the bzImage payload; if lc=3 grows past payload_size, retries lc=4.
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from patch_vmlinuz import (  # noqa: E402
    find_payload,
    parse_xz_params,
    xz_compress,
    xz_decompress,
)

SKIP_SITE = bytes.fromhex("48833d")  # cmp qword [rip+disp32], imm8
# 4.0.311 x64: cmpq $-1, [rip] ; jne decrypt ; xor %eax,%eax ; mov $6,%ecx
SKIP_TAIL = bytes.fromhex("ffff0f85")  # last disp byte + imm8=-1 + jne
XOR_ECX6 = bytes.fromhex("31c0b906000000")
INITRD_IMAGE = b"/initrd.image"


def elf_file_of(vmlinux: bytes, va: int) -> int | None:
    e_phoff = struct.unpack_from("<Q", vmlinux, 32)[0]
    e_phentsize = struct.unpack_from("<H", vmlinux, 54)[0]
    e_phnum = struct.unpack_from("<H", vmlinux, 56)[0]
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", vmlinux, o)[0]
        if p_type != 1:
            continue
        p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from("<QQQQ", vmlinux, o + 8)
        if p_vaddr <= va < p_vaddr + p_filesz:
            return p_offset + (va - p_vaddr)
    return None


def elf_va(vmlinux: bytes, file_off: int) -> int:
    e_phoff = struct.unpack_from("<Q", vmlinux, 32)[0]
    e_phentsize = struct.unpack_from("<H", vmlinux, 54)[0]
    e_phnum = struct.unpack_from("<H", vmlinux, 56)[0]
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", vmlinux, o)[0]
        if p_type != 1:
            continue
        p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from("<QQQQ", vmlinux, o + 8)
        if p_offset <= file_off < p_offset + p_filesz:
            return p_vaddr + (file_off - p_offset)
    raise SystemExit(f"no ELF mapping for {file_off:#x}")


def find_skip_and_target(vmlinux: bytes) -> tuple[int, int]:
    """Return (file_offset of xor eax,eax at skip site, file_offset of jmp target)."""
    site = None
    start = 0
    while True:
        i = vmlinux.find(SKIP_SITE, start)
        if i < 0:
            break
        # 48 83 3d disp32 ff | 0f 85 rel32 | 31 c0 b9 06 00 00 00
        if vmlinux[i + 6 : i + 10] == SKIP_TAIL and vmlinux[i + 14 : i + 21] == XOR_ECX6:
            site = i + 14  # 31 c0 ...
            break
        start = i + 1
    if site is None:
        raise SystemExit("IKMF decrypt skip site not found (need 4.0.306+ x64 vmlinuz)")

    s = vmlinux.find(INITRD_IMAGE)
    if s < 0:
        raise SystemExit("/initrd.image string not found")
    str_va = elf_va(vmlinux, s)
    # mov $imm32, %rdi  (48 c7 c7 imm32) with sign-extended kernel VA
    imm = struct.pack("<I", str_va & 0xFFFFFFFF)
    needle = b"\x48\xc7\xc7" + imm
    j = vmlinux.find(needle, site)
    if j < 0:
        raise SystemExit("could not find /initrd.image reference after skip site")
    # 4.0.311: jmp lands 0x28 bytes before that mov (open+write path)
    target = j - 0x28
    if vmlinux[target] != 0x48:
        raise SystemExit(f"unexpected jmp target opcode at {target:#x}")
    return site, target


def patch_vmlinuz(src: Path, dst: Path) -> None:
    orig = bytearray(src.read_bytes())
    payload_start, payload_size = find_payload(bytes(orig))
    vmlinux, xz_actual = xz_decompress(bytes(orig[payload_start:]))
    vmlinux = bytearray(vmlinux)
    site, target = find_skip_and_target(bytes(vmlinux))
    site_va = elf_va(bytes(vmlinux), site)
    target_va = elf_va(bytes(vmlinux), target)
    rel = target_va - (site_va + 5)
    vmlinux[site : site + 5] = bytes([0xE9]) + struct.pack("<i", rel)
    print(f"[xzskip] jmp {site_va:#x} -> {target_va:#x} rel={rel:#x}")

    params = parse_xz_params(bytes(orig), payload_start)
    new_xz = xz_compress(bytes(vmlinux), check=params["check"], filters=params["filters"])
    if len(new_xz) > payload_size:
        filters = []
        for f in params["filters"]:
            if f.get("id") == 33:
                f = dict(f)
                f["lc"] = 4
            filters.append(f)
        new_xz = xz_compress(bytes(vmlinux), check=params["check"], filters=filters)
        print(f"[xzskip] retried xz lc=4 size={len(new_xz)}")
    if len(new_xz) > payload_size:
        raise SystemExit(
            f"compressed payload {len(new_xz)} > original {payload_size}; "
            "refusing to grow bzImage"
        )
    prefix = bytes(orig[:payload_start])
    gap = b"\x00" * (payload_size - len(new_xz))
    suffix = bytes(orig[payload_start + payload_size :])
    out = prefix + new_xz + gap + suffix
    if len(out) != len(orig):
        raise SystemExit(f"size changed {len(orig)} -> {len(out)}")
    dst.write_bytes(out)
    print(f"[xzskip] wrote {dst} ({len(out)} bytes)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input_vmlinuz")
    ap.add_argument("output_vmlinuz")
    args = ap.parse_args()
    patch_vmlinuz(Path(args.input_vmlinuz), Path(args.output_vmlinuz))


if __name__ == "__main__":
    main()
