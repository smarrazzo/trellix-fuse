# trellix-fuse

Mount a **Trellix / McAfee Drive Encryption** volume and read it in the clear,
in the spirit of `dislocker-fuse`.

The tool exposes the encrypted volume as a single virtual file that decrypts on
read. Loop-mount that file and the filesystem inside appears normally.

```
trellix-fuse --disk /dev/sda3 --trellix /dev/sda4 --ppk <64 hex> /mnt/epe
mount -o loop,ro /mnt/epe/trellix-disk /mnt/clear
ls /mnt/clear
```

> Use it only on machines within the scope of an authorised engagement.

---

## What it handles

All four disk algorithms of `MCC_crypto_disk_algs`, recovered from
`EpeBootcode.efi`:

| id | Algorithm | Per-sector construction |
|---|---|---|
| 18 | AES-256-CBC | 128-bit CBC, IV = `E(K, n‖n‖n‖n)` |
| 17 | SBAES-256-CBC | 128-bit CBC, IV = `E(K, n‖n‖n‖n)` |
| 0 | RC5-12 | 64-bit CBC, IV = `(n, n ^ 0xD5E74364)`, no key expansion |
| 1 | RC5-18 | 64-bit CBC, IV = `(n, n ^ 0xD5E74364)`, no key expansion |

`n` is the **absolute LBA of the sector on the disk**. This matters more than it
sounds — see [The LBA base](#the-lba-base).

The algorithm id lives in `\System\AlgId.dat` on the preboot volume;
`--algid-file` reads it for you, and `--trellix` finds it by itself.

## Where the key comes from

The disk key is the deserialised content of `\System\SystemKey.dat`, which lives
on the product's own preboot partition (`McAfeeEpeReserved`, a FAT32 volume with
a replaced header). Two variants exist, and the product picks between them by
the presence of a file:

| Variant | Condition | Disk key |
|---|---|---|
| legacy | `AbSecPol.dat` absent | `SystemKey.dat` **XOR** PPK |
| secure | `AbSecPol.dat` present | `SystemKey.dat` **verbatim** — the PPK only validates the policy file |

The PPK is the value the TPM releases; on a machine with no pre-boot
authentication it can be captured on the SPI bus during boot.

`--trellix` detects the variant, derives the key, and checks the PPK with the
firmware's own test — you do not have to know which variant you are facing.

---

## Building

Dependencies: FUSE 3 and OpenSSL.

```bash
# Debian / Ubuntu / Kali
sudo apt install build-essential pkg-config libfuse3-dev libssl-dev

# Fedora
sudo dnf install gcc pkgconf-pkg-config fuse3-devel openssl-devel

# Arch
sudo pacman -S base-devel fuse3 openssl
```

Then:

```bash
gcc -O2 -Wall -Wextra -o trellix-fuse trellix-fuse.c \
    $(pkg-config --cflags --libs fuse3 libcrypto)
```

Single translation unit, no build system. It compiles warning-free with
`-Wall -Wextra`.

---

## Usage

### The easy path: a whole-disk image

If you have a full disk image or the device itself, the tool does everything —
reads the partition table, finds the Trellix partition by its type GUID, picks
the encrypted partition, derives the key, and works out the LBA base:

```bash
trellix-fuse --image disk.dd --ppk <64 hex> /mnt/epe
mount -o loop,ro /mnt/epe/trellix-disk /mnt/clear
```

Look before you leap:

```bash
trellix-fuse --image disk.dd --list-parts
```

```
table     : GPT, 5 partition(s)

  #        start LBA        sectors  type                                   name
  1             2048        1024000  C12A7328-F81F-11D2-BA4B-00A0C93EC93B   (ESP)
  4        123456789         102400  38EDAEA1-E0D5-4888-A970-8E03E60BF06A   <-- Trellix
```

### Live device

```bash
trellix-fuse --disk /dev/sda3 --trellix /dev/sda4 --ppk <64 hex> /mnt/epe
```

With `--disk` pointing at a partition block device, the start LBA is read
straight from sysfs — nothing else to specify.

### Two separate partition images

The awkward case: you extracted the partitions individually, so neither image
carries its absolute position on the disk. The tool recovers it analytically
(see below):

```bash
trellix-fuse --disk encrypted.img --trellix trellix.img --ppk <64 hex> /mnt/epe
```

### If you already have the disk key

```bash
trellix-fuse --disk /dev/sda3 --key <64 hex> --lba-base 2048 /mnt/epe
```

### Decrypt to a file instead of mounting

```bash
trellix-fuse --image disk.dd --ppk <64 hex> --dump clear.img
```

---

## The LBA base

**The single most common reason this tool appears to work but silently
corrupts.** Read this section.

The firmware encrypts each sector using its **absolute LBA on the disk** as the
IV input. If you feed the tool a partition image, that image does not carry its
own start LBA anywhere, and a wrong base produces a subtle failure:

> In CBC, only the **first block** of a sector depends on the IV. A wrong LBA
> base therefore corrupts only the **first 16 bytes of every sector**. The
> filesystem will appear to mount. Directory listings will look fine. Every
> sector is wrong.

And the disk format carries **no integrity check whatsoever**, so nothing will
tell you.

The tool handles this three ways, in order:

1. **sysfs** — if `--disk` is a partition block device, the base is read from
   the kernel.
2. **Analytic recovery** — because the IV of sector *n* is a known function of
   *n*, and only the first block depends on it, 16 bytes of known plaintext are
   enough to *invert* *n* algebraically. NTFS, exFAT and FAT32 all provide those
   16 bytes at the start of a volume. No scanning involved.
3. **Confirmation before mounting** — whatever base was chosen, the tool
   decrypts the start of the region and requires a full first-cipher-block
   filesystem signature. **It refuses to mount if this fails.**

To see the computation on its own:

```bash
trellix-fuse --disk encrypted.img --trellix trellix.img --ppk <64 hex> --find-lba
```

```
analytic LBA base recovery
  the IV of sector n is a known function of n, and in CBC only the
  first block depends on it: 16 bytes of known plaintext are therefore
  enough to recover n, with no scanning.

  anchor    : NTFS (boot sector)
  algorithm : AES-256-CBC (id 18), encrypted IV
  LBA base  : 2048   (the first sector of the region is sector 2048 of the original disk)
  check     : NTFS, base confirmed
```

`--force-lba` overrides the refusal. Do not use it on a read-write mount unless
you have another reason to trust the base.

---

## When it does not work

### `--probe` — sweep algorithms and bases

```bash
trellix-fuse --disk encrypted.img --key <64 hex> --probe
```

It tries every algorithm against every plausible base and tells you which
combination yields a recognisable filesystem. The important distinction in its
output:

- `[base confirmed]` — key **and** sector numbering are both right. Mount it.
- `[key ok, base NOT confirmed]` — the key is right, the numbering is not. A
  signature was recognised beyond byte 16, which is exactly the situation that
  mounts and corrupts. Find the real base before going further.
- `nothing recognisable` — wrong key, wrong offset, or wrong algorithm.

### Common causes, in order of likelihood

| Symptom | Cause |
|---|---|
| No signature at all | Wrong disk key, or `--offset` misses the start of the encrypted region |
| Key ok, base never confirmed | `--disk` is a partition image; pass its start LBA as `--lba-base` |
| `no FAT32 volume found` | `--trellix` points at a partition while the header LBA is absolute — retry with the whole disk plus `--trellix-offset`, or pass `--pbfs-lba N` |
| Garbage beyond a certain offset | The volume is only partially encrypted (conversion in progress) |

### The `+0x2C` field

The EPE header field that names the preboot volume's location does **not** mean
the same thing on every deployment: on at least one fleet it holds the **end**
LBA rather than the start (`102432 - 102400 = 32`). The tool tries both
readings, then falls back to scanning for the FAT32 boot sector, then gives up
and asks for `--pbfs-lba`. You should not normally have to care.

---

## Writing

`--rw` gives a fully writable mount. Writes are re-encrypted sector by sector,
with read-modify-write for unaligned writes.

```bash
trellix-fuse --disk /dev/sda3 --key <hex> --lba-base 2048 --rw /mnt/epe
mount -o loop /mnt/epe/trellix-disk /mnt/clear
```

A read-write mount **refuses to start unless the LBA base is confirmed**,
because getting it wrong destroys data silently and irreversibly.

`--verify-writes` reads each sector back, decrypts it and requires a match. This
catches a failing drive, a lying cache or a transport error. It does **not**
catch a wrong LBA base — the read-back uses the same sector number the write
used, so it round-trips perfectly while the firmware sees 16 corrupt bytes in
every sector. Only the mount-time confirmation covers that.

---

## Integrity checks

The product's metadata sectors carry a checksum computed so the whole 512-byte
sector sums to zero. Bulk data sectors carry nothing. These checks are
transcribed from the firmware (`get_valid_epe_header`, `EPE_calc_sector_checksum`):

```bash
trellix-fuse --check-sector /dev/sda4          # verify one metadata sector
trellix-fuse --disk /dev/sda3 --epe-header /dev/sda4 --key <hex> /mnt/epe
```

---

## Option reference

Run `trellix-fuse --help` for the full list. The ones that matter:

| Option | Meaning |
|---|---|
| `--image PATH` | whole-disk image or device; finds everything itself |
| `--disk PATH` | the encrypted partition, or an image of it |
| `--trellix PATH` | the `McAfeeEpeReserved` partition; derives the key |
| `--ppk HEX` / `--ppk-file` | the TPM-released PPK, 32 bytes |
| `--key HEX` | the disk key directly, if you already have it |
| `--systemkey PATH` | `SystemKey.dat` extracted by hand |
| `--secure` | force the secure variant (no XOR) |
| `--lba-base N` | absolute sector number of the region's first sector |
| `--algid N` / `--algid-file` | algorithm selection |
| `--probe` | sweep algorithms and bases, mount nothing |
| `--find-lba` | compute the LBA base, mount nothing |
| `--dump FILE` | write the decrypted region to a file |
| `--list-parts` | print the partition table and exit |
| `--rw` | writable mount |

Standard FUSE options go after the mountpoint: `-f` (foreground),
`-o allow_other`, `-s` (single-threaded).

---

## Unmounting

```bash
umount /mnt/clear
fusermount3 -u /mnt/epe
```

---

## Notes

- Read-only by default.
- Sector size is 512 unless `--sector-size` says otherwise. `--trellix` assumes
  512, because both the sysfs LBA and the PBFS LBA are expressed in those units.
- `--raw-iv` switches the AES family to using the raw sector-number block as the
  IV instead of its encryption. Only worth trying if `--probe` fails everywhere
  in the default mode.
- The tool never writes to the Trellix partition. It only reads `AlgId.dat`,
  `SystemKey.dat` and `AbSecPol.dat` from it.
