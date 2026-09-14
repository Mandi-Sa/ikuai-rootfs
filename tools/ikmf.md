# 4.0.306+ x64 rootfs (IKMF)

Official `boot/rootfs` on 4.0.306 and later is still RSA-signed, but the
body cipher and the 0x294-byte trailer changed (`IKMF` at trailer+20).

## Unpack

The kernel decrypts initrd during boot. This tree boots that kernel in QEMU
and copies the plaintext xz out of guest memory at the `unxz()` call:

```
./build.sh unpack iKuai8_x64_4.0.311_BuildYYYYMMDDHHMM.iso -qemu
```

Needs root, KVM (`/dev/kvm`), and `qemu-system-x86_64`. Result is the same
layout as v1/v2/v3 unpack: `rootfs-unpack/rootfs/` plus `rootfs-unpack/vmlinuz`.

`-v3` still unpacks 4.0.305 and earlier. If `-qemu` is omitted and the image
has an IKMF trailer, unpack falls back to QEMU automatically.

## Pack a modified ramdisk

After unpack + edit:

```
./build.sh pack_bin 10001 4.0.311 0 -xzskip
```

That does three things:

1. Compress the edited ext4 as plaintext xz.
2. Append a 0x194 IKMF MD5 trailer (`tools/ikmf_sign_initrd.py`) so unmodified
   `ik_core.ko` accepts the ramdisk.
3. Patch `vmlinuz` so an already-xz ramdisk skips IKMF decrypt, and so the
   mapped initrd is copied into `j4m2zc` / `k7p9vn` (the two kernel globals
   `ik_core` hashes). Cave is the IKMF-parse bytes that jump skips.

`pack_iso` accepts the same `-xzskip` flag. Verified on 4.0.311 x64 with
stock `ik_core.ko`: guest `/proc/uptime` advanced past 1000s with no wrap.

## Trailer

Official encrypted `boot/rootfs` ends with 0x294 bytes (0x194 prefix + 256-byte
RSA). `ik_core` hashes `k7p9vn - 0x194` bytes and compares 16 bytes at that
offset; packed xz-skip images therefore append only the 0x194 prefix:

| offset | size | field |
|--------|------|--------|
| 0      | 16   | md3 (`MD5(md2)`, see below) |
| 16     | 4    | dword mixed into md2 |
| 20     | 4    | `IKMF` |
| 24     | 4    | version (3 on 4.0.311) |
| 36     | 8    | plaintext/body length |
| 44     | 8    | body length (copy) |

md chain used by `ik_core`:

```
md1 = MD5(body)
md2 = MD5(md1[8:16] + md1[0:8] + dword)
md3 = MD5(md2)
```
