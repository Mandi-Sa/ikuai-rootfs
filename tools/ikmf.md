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

IKMF re-signing is not included. After unpack + edit, pack a plaintext xz
initrd and a kernel that skips IKMF when the ramdisk is already xz:

```
./build.sh pack_bin 10001 4.0.311 0 -xzskip
```

`pack_iso` accepts the same `-xzskip` flag. Verified on 4.0.311 x64.

## Trailer

Last 0x294 bytes of `initrd_length`:

| offset | size | field |
|--------|------|--------|
| 0      | 16   | seed material (not the working cipher key) |
| 16     | 4    | nibble-CRC hash of the plaintext xz (little-endian, double-hash) |
| 20     | 4    | `IKMF` |
| 24     | 4    | version (3 on 4.0.311) |
| 36     | 8    | plaintext/body length |
| 0x194  | 256  | RSA signature of the preceding bytes |
