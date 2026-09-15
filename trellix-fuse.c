/*
 * trellix-fuse - expose a Trellix/McAfee Drive Encryption volume as a plain
 *                decrypted image file, in the spirit of dislocker-fuse.
 *
 * Mount it, and you get a single virtual file that decrypts on read. Loop-mount
 * that file and the filesystem inside appears in the clear:
 *
 *     trellix-fuse --disk /dev/sda3 --ppk <hex> --systemkey SystemKey.dat /mnt/epe
 *     mount -o loop,ro /mnt/epe/trellix-disk /mnt/clear
 *
 * All four disk algorithms of MCC_crypto_disk_algs are implemented:
 * AES-256-CBC (id 18), SBAES-256-CBC (id 17), RC5-12 (id 0), RC5-18 (id 1).
 * \System\AlgId.dat holds the id; --algid-file reads it for you.
 *
 * The disk key K itself is the deserialised content of \System\SystemKey.dat,
 * which on the legacy autoboot path is stored XORed with the TPM-sealed PPK.
 *
 * Read-only by default; --rw gives a fully writable mount, like dislocker-fuse.
 * A read-write mount refuses to start unless the sector numbering base has
 * been confirmed, because getting it wrong destroys data silently.
 *
 * Build:
 *     gcc -O2 -Wall -o trellix-fuse trellix-fuse.c \
 *         $(pkg-config --cflags --libs fuse3 libcrypto)
 *
 * Debian/Ubuntu deps: libfuse3-dev libssl-dev
 */

#define FUSE_USE_VERSION 31
#define _GNU_SOURCE

#include <fuse3/fuse.h>
#include <openssl/evp.h>

#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <pthread.h>
#include <unistd.h>

#define KEY_LEN 32
#define MAX_SECTOR 4096

/* ------------------------------------------------------------------ state */

static struct {
    int      fd;              /* the encrypted disk or image            */
    uint8_t  key[KEY_LEN];
    uint64_t offset;          /* byte offset of the encrypted region    */
    uint64_t size;            /* byte length of the encrypted region    */
    uint64_t lba_base;        /* sector number of the region's 1st sector */
    unsigned sector;          /* sector size, 512 unless told otherwise */
    int      algid;           /* 18 AES, 17 SBAES, 0 RC5-12, 1 RC5-18   */
    int      raw_iv;          /* AES family: skip the tweak encryption  */
    int      alg_given, iv_given;
    int      rw;              /* read-write mount                       */
    int      verify_writes;   /* read back and compare after each write */
    uint8_t  rc5ctx[256];     /* RC5 "schedule": the raw key, twice     */
    const char *vname;        /* name of the virtual file               */
} g = { .fd = -1, .sector = 512, .algid = 18, .vname = "trellix-disk" };

/* --------------------------------------------------------------- crypto */
/*
 * Four algorithms are registered by MCC_crypto_disk_algs::init in mfecc.efi.
 * Their numeric id and name come from the 344-byte descriptor each one copies
 * out of its slot-0 function:
 *
 *   id 18 (0x12)  "AES-256-CBC"     Epe_aesfips_*  (AES-NI when available)
 *   id 17 (0x11)  "SBAES-256-CBC"   Epe_aes256_*_c (software AES, SafeBoot)
 *   id  0         "RC5-12"          Epe_rc512_crypt
 *   id  1         "RC5-18"          Epe_rc518_crypt
 *
 * AES family, per sector n (sub_1001984A -> sub_100193A6 -> sub_1001928E):
 *     tweak = [n|n|n|n] little-endian, encrypted IN PLACE with the data key,
 *     the result is the CBC IV for that sector.
 *
 * RC5 family, per sector n (Epe_rc512_crypt / Epe_rc518_crypt):
 *     64-bit blocks, CBC, chained from A = n and B = n ^ 0xD5E74364 - the IV
 *     is the sector number itself, no block encryption of it.
 *     There is NO key schedule: set_key (sub_1001785F) merely zeroes a
 *     256-byte context and copies the raw key into it twice, at offset 0 and
 *     at offset 128. The round subkeys S[] are read straight out of that,
 *     through a window that walks by +104 bytes per block for RC5-12 and by
 *     -104 for RC5-18, wrapped to 128. Round i uses S[(2i) mod 32].
 */

#define ALG_AES256   18
#define ALG_SBAES256 17
#define ALG_RC5_12    0
#define ALG_RC5_18    1

#define RC5_MAGIC 0xD5E74364u
#define RC5_CTX   256          /* bytes */

static const struct { int id; const char *name; } ALGS[] = {
    { ALG_AES256,   "AES-256-CBC"   },
    { ALG_SBAES256, "SBAES-256-CBC" },
    { ALG_RC5_12,   "RC5-12"        },
    { ALG_RC5_18,   "RC5-18"        },
};
#define NALGS ((int)(sizeof(ALGS)/sizeof(ALGS[0])))

static const char *alg_name(int id)
{
    int i;
    for (i = 0; i < NALGS; i++) if (ALGS[i].id == id) return ALGS[i].name;
    return "inconnu";
}

/* ------------------------------------------------------------ RC5 core */

static inline uint32_t rotl32(uint32_t v, unsigned c) { c &= 31; return c ? (v << c) | (v >> (32 - c)) : v; }
static inline uint32_t rotr32(uint32_t v, unsigned c) { c &= 31; return c ? (v >> c) | (v << (32 - c)) : v; }
static inline uint32_t ld32(const uint8_t *p)
{ return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static inline void st32(uint8_t *p, uint32_t v)
{ p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

/* The "key schedule": the raw key, twice, in a zeroed 256-byte context. */
static void rc5_setkey(uint8_t ctx[RC5_CTX], const uint8_t *key, size_t klen)
{
    memset(ctx, 0, RC5_CTX);
    if (klen > 128) klen = 128;
    memcpy(ctx, key, klen);
    memcpy(ctx + 128, key, klen);
}

static void rc5_decrypt_sector(const uint8_t ctx[RC5_CTX], int rounds, int step,
                               uint32_t lba, uint8_t *buf, unsigned len)
{
    uint32_t Ap = lba, Bp = lba ^ RC5_MAGIC;
    unsigned koff = 0, nb = len / 8, b;

    for (b = 0; b < nb; b++) {
        uint8_t *p = buf + 8 * b;
        const uint8_t *S = ctx + koff;
        uint32_t A = ld32(p), B = ld32(p + 4);
        uint32_t cA = A, cB = B;              /* chain from the ciphertext */
        int i;

        for (i = rounds; i >= 1; i--) {
            unsigned j = (unsigned)(2 * i) & 31u;
            B = A ^ rotr32(B - ld32(S + 4 * (j + 1)), A);
            A = B ^ rotr32(A - ld32(S + 4 * j),       B);
        }
        B = Bp ^ (B - ld32(S + 4));
        A = Ap ^ (A - ld32(S));

        st32(p, A); st32(p + 4, B);
        Ap = cA; Bp = cB;
        koff = (unsigned)((int)koff + step) & 0x7Fu;
    }
}

/* Decrypt block 0 through the rounds only, stopping before the CBC XOR.
 * Returns A' = A - S[0] and B' = B - S[1], from which the chaining values
 * (and therefore the sector number) can be recovered given known plaintext. */
static void rc5_first_block_raw(const uint8_t ctx[RC5_CTX], int rounds,
                                const uint8_t blk[8], uint32_t *outA, uint32_t *outB)
{
    const uint8_t *S = ctx;                  /* block 0 -> window offset 0 */
    uint32_t A = ld32(blk), B = ld32(blk + 4);
    int i;
    for (i = rounds; i >= 1; i--) {
        unsigned j = (unsigned)(2 * i) & 31u;
        B = A ^ rotr32(B - ld32(S + 4 * (j + 1)), A);
        A = B ^ rotr32(A - ld32(S + 4 * j),       B);
    }
    *outB = B - ld32(S + 4);
    *outA = A - ld32(S);
}

static void rc5_encrypt_sector(const uint8_t ctx[RC5_CTX], int rounds, int step,
                               uint32_t lba, uint8_t *buf, unsigned len)
{
    uint32_t Ap = lba, Bp = lba ^ RC5_MAGIC;
    unsigned koff = 0, nb = len / 8, b;

    for (b = 0; b < nb; b++) {
        uint8_t *p = buf + 8 * b;
        const uint8_t *S = ctx + koff;
        uint32_t A = ld32(p), B = ld32(p + 4);
        int i;

        A = ld32(S)     + (Ap ^ A);
        B = ld32(S + 4) + (Bp ^ B);
        for (i = 1; i <= rounds; i++) {
            unsigned j = (unsigned)(2 * i) & 31u;
            A = ld32(S + 4 * j)       + rotl32(A ^ B, B);
            B = ld32(S + 4 * (j + 1)) + rotl32(B ^ A, A);
        }
        Ap = A; Bp = B;
        st32(p, A); st32(p + 4, B);
        koff = (unsigned)((int)koff + step) & 0x7Fu;
    }
}

/* ------------------------------------------------------------ AES core */

static int aes_sector(uint64_t lba, const uint8_t *in, uint8_t *out,
                      unsigned len, int encrypt)
{
    uint8_t tweak[16], iv[16];
    uint32_t n = (uint32_t)lba;          /* the firmware stores 4 dwords */
    int outl = 0, rc = -1;
    EVP_CIPHER_CTX *c = NULL;

    st32(tweak +  0, n);                 /* explicitly little-endian */
    st32(tweak +  4, n);
    st32(tweak +  8, n);
    st32(tweak + 12, n);

    if (!(c = EVP_CIPHER_CTX_new()))
        return -1;

    if (g.raw_iv) {
        memcpy(iv, tweak, 16);
    } else {
        /* IV = AES-256-Encrypt(K, tweak), in place - confirmed at 0x100193CB */
        if (EVP_EncryptInit_ex(c, EVP_aes_256_ecb(), NULL, g.key, NULL) != 1)
            goto out;
        EVP_CIPHER_CTX_set_padding(c, 0);
        if (EVP_EncryptUpdate(c, iv, &outl, tweak, 16) != 1 || outl != 16)
            goto out;
        if (EVP_CIPHER_CTX_reset(c) != 1)
            goto out;
    }

    if (encrypt) {
        if (EVP_EncryptInit_ex(c, EVP_aes_256_cbc(), NULL, g.key, iv) != 1)
            goto out;
        EVP_CIPHER_CTX_set_padding(c, 0);
        if (EVP_EncryptUpdate(c, out, &outl, in, (int)len) != 1)
            goto out;
    } else {
        if (EVP_DecryptInit_ex(c, EVP_aes_256_cbc(), NULL, g.key, iv) != 1)
            goto out;
        EVP_CIPHER_CTX_set_padding(c, 0);
        if (EVP_DecryptUpdate(c, out, &outl, in, (int)len) != 1)
            goto out;
    }
    rc = 0;
out:
    EVP_CIPHER_CTX_free(c);
    return rc;
}

static int decrypt_sector(uint64_t lba, const uint8_t *in, uint8_t *out,
                          unsigned len)
{
    switch (g.algid) {
    case ALG_AES256:
    case ALG_SBAES256:
        return aes_sector(lba, in, out, len, 0);
    case ALG_RC5_12:
        memcpy(out, in, len);
        rc5_decrypt_sector(g.rc5ctx, 12,  104, (uint32_t)lba, out, len);
        return 0;
    case ALG_RC5_18:
        memcpy(out, in, len);
        rc5_decrypt_sector(g.rc5ctx, 18, -104, (uint32_t)lba, out, len);
        return 0;
    default:
        return -1;
    }
}

static int encrypt_sector(uint64_t lba, const uint8_t *in, uint8_t *out,
                          unsigned len)
{
    switch (g.algid) {
    case ALG_AES256:
    case ALG_SBAES256:
        return aes_sector(lba, in, out, len, 1);
    case ALG_RC5_12:
        memcpy(out, in, len);
        rc5_encrypt_sector(g.rc5ctx, 12,  104, (uint32_t)lba, out, len);
        return 0;
    case ALG_RC5_18:
        memcpy(out, in, len);
        rc5_encrypt_sector(g.rc5ctx, 18, -104, (uint32_t)lba, out, len);
        return 0;
    default:
        return -1;
    }
}

/* Read [pos, pos+len) of the *plaintext* region. Handles reads that do not
 * start or end on a sector boundary. */
static ssize_t read_plain(uint8_t *buf, size_t len, uint64_t pos)
{
    uint8_t cin[MAX_SECTOR + 16], cout[MAX_SECTOR + 16];
    size_t done = 0;

    if (pos >= g.size)
        return 0;
    if (pos + len > g.size)
        len = g.size - pos;

    while (done < len) {
        uint64_t abs    = pos + done;
        uint64_t sidx   = abs / g.sector;          /* sector within region */
        unsigned within = (unsigned)(abs % g.sector);
        unsigned chunk  = g.sector - within;
        ssize_t  got;

        if (chunk > len - done)
            chunk = (unsigned)(len - done);

        got = pread(g.fd, cin, g.sector,
                    (off_t)(g.offset + sidx * (uint64_t)g.sector));
        if (got != (ssize_t)g.sector) {
            /* The region was validated against the backing size at startup,
             * so a short read here is a real I/O failure, never EOF. Never
             * fabricate plaintext out of a zero-filled buffer. */
            if (done) return (ssize_t)done;          /* report what we got */
            return (got < 0) ? -errno : -EIO;
        }

        if (decrypt_sector(g.lba_base + sidx, cin, cout, g.sector) != 0)
            return done ? (ssize_t)done : -EIO;

        memcpy(buf + done, cout + within, chunk);
        done += chunk;
    }
    return (ssize_t)done;
}

/* Serialises the read-modify-write of a partially covered sector. The kernel
 * currently holds i_rwsem across buffered writes to one inode, but nothing
 * here may depend on that. */
static pthread_mutex_t rmw_lock = PTHREAD_MUTEX_INITIALIZER;

/* Write [pos, pos+len) of the *plaintext* region. Sectors that are only
 * partly covered are read-modify-written: decrypt, patch, re-encrypt. */
static ssize_t write_plain(const uint8_t *buf, size_t len, uint64_t pos)
{
    uint8_t cin[MAX_SECTOR + 16], plain[MAX_SECTOR + 16], cout[MAX_SECTOR + 16];
    uint8_t back[MAX_SECTOR + 16], chk[MAX_SECTOR + 16];
    size_t done = 0;

    if (!g.rw)
        return -EROFS;
    if (pos >= g.size)
        return -ENOSPC;
    if (pos + len > g.size)
        len = g.size - pos;

    while (done < len) {
        uint64_t abs    = pos + done;
        uint64_t sidx   = abs / g.sector;
        unsigned within = (unsigned)(abs % g.sector);
        unsigned chunk  = g.sector - within;
        off_t    where  = (off_t)(g.offset + sidx * (uint64_t)g.sector);
        int      partial;
        ssize_t  n;

        if (chunk > len - done)
            chunk = (unsigned)(len - done);
        partial = (chunk != g.sector);

        /* Lock unconditionally: a full-sector write landing between a
         * partial write's pread and its pwrite would be lost. */
        pthread_mutex_lock(&rmw_lock);

        if (!partial) {
            memcpy(plain, buf + done, g.sector);
        } else {
            n = pread(g.fd, cin, g.sector, where);
            if (n != (ssize_t)g.sector) {
                pthread_mutex_unlock(&rmw_lock);
                if (done) return (ssize_t)done;
                return (n < 0) ? -errno : -EIO;
            }
            if (decrypt_sector(g.lba_base + sidx, cin, plain, g.sector) != 0) {
                pthread_mutex_unlock(&rmw_lock);
                return done ? (ssize_t)done : -EIO;
            }
            memcpy(plain + within, buf + done, chunk);
        }

        if (encrypt_sector(g.lba_base + sidx, plain, cout, g.sector) != 0) {
            pthread_mutex_unlock(&rmw_lock);
            return done ? (ssize_t)done : -EIO;
        }

        n = pwrite(g.fd, cout, g.sector, where);
        if (n != (ssize_t)g.sector) {
            pthread_mutex_unlock(&rmw_lock);
            if (done) return (ssize_t)done;
            return (n < 0) ? -errno : -EIO;
        }

        /* The on-disk format carries no integrity of its own. When asked, we
         * supply it ourselves: read the sector back, decrypt it, and require
         * it to match what we meant to store.
         *
         * What this catches: a failing drive, a lying cache, a silent short
         * write, a transport error.
         * What it CANNOT catch: a wrong --lba-base. The read-back decrypts
         * with the same (wrong) sector number the write encrypted with, so it
         * round-trips perfectly while the firmware sees 16 corrupt bytes in
         * every sector. Only the mount-time base confirmation covers that. */
        if (g.verify_writes) {
            n = pread(g.fd, back, g.sector, where);
            if (n != (ssize_t)g.sector
                || decrypt_sector(g.lba_base + sidx, back, chk, g.sector) != 0
                || memcmp(chk, plain, g.sector) != 0) {
                pthread_mutex_unlock(&rmw_lock);
                fprintf(stderr, "trellix-fuse: sector %llu written but reads back "
                        "inconsistent - aborting\n",
                        (unsigned long long)(g.lba_base + sidx));
                return done ? (ssize_t)done : -EIO;
            }
        }

        pthread_mutex_unlock(&rmw_lock);
        done += chunk;
    }
    return (ssize_t)done;
}

/* ----------------------------------------------------------------- fuse */

static int is_ours(const char *path)
{
    return path[0] == '/' && strcmp(path + 1, g.vname) == 0;
}

static int cf_getattr(const char *path, struct stat *st,
                      struct fuse_file_info *fi)
{
    (void)fi;
    memset(st, 0, sizeof(*st));
    if (strcmp(path, "/") == 0) {
        st->st_mode  = S_IFDIR | 0555;
        st->st_nlink = 2;
        return 0;
    }
    if (is_ours(path)) {
        st->st_mode  = S_IFREG | (g.rw ? 0644 : 0444);
        st->st_nlink = 1;
        st->st_size  = (off_t)g.size;
        st->st_blocks = (blkcnt_t)(g.size / 512);
        return 0;
    }
    return -ENOENT;
}

static int cf_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t off, struct fuse_file_info *fi,
                      enum fuse_readdir_flags flags)
{
    (void)off; (void)fi; (void)flags;
    if (strcmp(path, "/") != 0)
        return -ENOENT;
    filler(buf, ".",  NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    filler(buf, g.vname, NULL, 0, 0);
    return 0;
}

static int cf_open(const char *path, struct fuse_file_info *fi)
{
    if (!is_ours(path))
        return -ENOENT;
    if (!g.rw && (fi->flags & O_ACCMODE) != O_RDONLY)
        return -EROFS;       /* read-only unless --rw was given */
    return 0;
}

static int cf_read(const char *path, char *buf, size_t len, off_t off,
                   struct fuse_file_info *fi)
{
    (void)fi;
    if (!is_ours(path))
        return -ENOENT;
    if (off < 0)
        return -EINVAL;
    if (len > INT_MAX) len = INT_MAX;
    return (int)read_plain((uint8_t *)buf, len, (uint64_t)off);
}

static int cf_write(const char *path, const char *buf, size_t len, off_t off,
                    struct fuse_file_info *fi)
{
    (void)fi;
    if (!is_ours(path))
        return -ENOENT;
    if (!g.rw)
        return -EROFS;
    if (off < 0)
        return -EINVAL;
    if (len > INT_MAX) len = INT_MAX;
    return (int)write_plain((const uint8_t *)buf, len, (uint64_t)off);
}

/* The image has a fixed size. Accept a truncate to exactly that, which is
 * what mount(8) and mkfs may probe with; refuse anything that would resize. */
static int cf_truncate(const char *path, off_t size, struct fuse_file_info *fi)
{
    (void)fi;
    if (!is_ours(path))
        return -ENOENT;
    if (!g.rw)
        return -EROFS;
    return ((uint64_t)size == g.size) ? 0 : -EPERM;
}

static int cf_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
    (void)datasync; (void)fi;
    if (!is_ours(path))
        return -ENOENT;
    return (fsync(g.fd) == 0) ? 0 : -errno;
}

static const struct fuse_operations cf_ops = {
    .getattr  = cf_getattr,
    .readdir  = cf_readdir,
    .open     = cf_open,
    .read     = cf_read,
    .write    = cf_write,
    .truncate = cf_truncate,
    .fsync    = cf_fsync,
};

/* ------------------------------------------------- tables de partitions */
/*
 * Enough GPT and MBR parsing to work on a whole-disk image: find the Trellix
 * partition by its type GUID, and the encrypted partition by index or by
 * elimination. On an image there is no sysfs to ask, so the partition table
 * is the only place the absolute start LBA can come from - and that LBA is
 * exactly what the sector IV derivation needs.
 */

#define MAX_PARTS 128

struct part {
    uint64_t start, count;      /* in 512-byte LBAs */
    uint8_t  type[16];          /* GPT type GUID, or {mbr_type,0,...} */
    char     name[40];          /* GPT name, ASCII-folded */
    int      mbr_type;          /* -1 for GPT */
};

/* 38EDAEA1-E0D5-4888-A970-8E03E60BF06A, mixed-endian on disk */
static const uint8_t EPE_TYPE_GUID[16] = {
    0xA1,0xAE,0xED,0x38, 0xD5,0xE0, 0x88,0x48,
    0xA9,0x70, 0x8E,0x03,0xE6,0x0B,0xF0,0x6A
};
/* C12A7328-F81F-11D2-BA4B-00A0C93EC93B : EFI System Partition */
static const uint8_t ESP_TYPE_GUID[16] = {
    0x28,0x73,0x2A,0xC1, 0x1F,0xF8, 0xD2,0x11,
    0xBA,0x4B, 0x00,0xA0,0xC9,0x3E,0xC9,0x3B
};

static void guid_str(const uint8_t g[16], char out[40])
{
    snprintf(out, 40,
        "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        g[3],g[2],g[1],g[0], g[5],g[4], g[7],g[6],
        g[8],g[9], g[10],g[11],g[12],g[13],g[14],g[15]);
}

static uint64_t ld64(const uint8_t *p)
{ return (uint64_t)ld32(p) | ((uint64_t)ld32(p + 4) << 32); }

static int scan_gpt(int fd, struct part *out, int max)
{
    uint8_t hdr[512], *tab;
    uint64_t ent_lba;
    uint32_t nent, esz;
    int n = 0, i;

    if (pread(fd, hdr, 512, 512) != 512)          return -1;
    if (memcmp(hdr, "EFI PART", 8))               return -1;
    ent_lba = ld64(hdr + 72);
    nent    = ld32(hdr + 80);
    esz     = ld32(hdr + 84);
    if (!nent || nent > 1024 || esz < 128 || esz > 4096) return -1;
    if (nent > (uint32_t)max) nent = (uint32_t)max;

    if (!(tab = malloc((size_t)nent * esz)))      return -1;
    if (pread(fd, tab, (size_t)nent * esz, (off_t)(ent_lba * 512))
        != (ssize_t)((size_t)nent * esz)) { free(tab); return -1; }

    for (i = 0; i < (int)nent; i++) {
        const uint8_t *e = tab + (size_t)i * esz;
        static const uint8_t zero[16] = { 0 };
        int k;
        if (!memcmp(e, zero, 16)) continue;       /* unused entry */
        memcpy(out[n].type, e, 16);
        out[n].start    = ld64(e + 32);
        out[n].count    = ld64(e + 40) - out[n].start + 1;
        out[n].mbr_type = -1;
        for (k = 0; k < 36 && k < (int)sizeof(out[n].name) - 1; k++) {
            unsigned c = (unsigned)e[56 + 2 * k] | ((unsigned)e[57 + 2 * k] << 8);
            if (!c) break;
            out[n].name[k] = (c >= 0x20 && c < 0x7F) ? (char)c : '?';
        }
        out[n].name[k] = 0;
        if (++n >= max) break;
    }
    free(tab);
    return n;
}

static int scan_mbr(int fd, struct part *out, int max)
{
    uint8_t s[512];
    int n = 0, i;

    if (pread(fd, s, 512, 0) != 512)              return -1;
    if (s[510] != 0x55 || s[511] != 0xAA)         return -1;
    for (i = 0; i < 4 && n < max; i++) {
        const uint8_t *e = s + 446 + 16 * i;
        if (!e[4]) continue;                      /* empty */
        if (e[4] == 0xEE) return -1;              /* protective MBR: it is GPT */
        memset(&out[n], 0, sizeof(out[n]));
        out[n].mbr_type = e[4];
        out[n].type[0]  = e[4];
        out[n].start    = ld32(e + 8);
        out[n].count    = ld32(e + 12);
        snprintf(out[n].name, sizeof(out[n].name), "type 0x%02X", e[4]);
        n++;
    }
    return n;
}

static int scan_parts(int fd, struct part *out, int max, const char **kind)
{
    int n = scan_gpt(fd, out, max);
    if (n > 0) { *kind = "GPT"; return n; }
    n = scan_mbr(fd, out, max);
    if (n > 0) { *kind = "MBR"; return n; }
    *kind = NULL;
    return 0;
}

static void list_parts(FILE *o, const struct part *p, int n, const char *kind)
{
    char g[40];
    int i;
    fprintf(o, "table     : %s, %d partition(s)\n\n", kind, n);
    fprintf(o, "  %-3s %14s %14s  %-38s %s\n",
           "#", "start LBA", "sectors", "type", "name");
    for (i = 0; i < n; i++) {
        const char *tag = "";
        if (p[i].mbr_type < 0) {
            guid_str(p[i].type, g);
            if (!memcmp(p[i].type, EPE_TYPE_GUID, 16)) tag = "  <-- Trellix";
            else if (!memcmp(p[i].type, ESP_TYPE_GUID, 16)) tag = "  (ESP)";
        } else {
            snprintf(g, sizeof(g), "MBR 0x%02X", p[i].mbr_type);
        }
        fprintf(o, "  %-3d %14llu %14llu  %-38s %s%s\n", i + 1,
               (unsigned long long)p[i].start, (unsigned long long)p[i].count,
               g, p[i].name, tag);
    }
    fprintf(o, "\n");
}

/* ------------------------------------------------------- lecteur FAT32 */
/*
 * A minimal read-only FAT32 reader, just enough to pull a handful of files out
 * of the PBFS. The PBFS is a plain FAT32 volume (EPE_create_fat32_pbfs) sitting
 * at the LBA the EPE partition header names, so nothing exotic is needed.
 */

struct fat32 {
    int      fd;
    uint64_t base;          /* byte offset of the volume in fd            */
    unsigned bps, spc, rsvd, nfats;
    uint32_t fatsz, root_clus, nclus;
    uint64_t fat_off, data_off;
    uint64_t vol_end;       /* hard bound: nothing is read past this */
};

static int fat32_open(struct fat32 *f, int fd, uint64_t base, uint64_t vol_bytes)
{
    uint8_t s[512];
    uint32_t tot;
    uint64_t sys, nc;

    memset(f, 0, sizeof(*f));
    f->fd = fd; f->base = base;
    if (pread(fd, s, 512, (off_t)base) != 512)                 return -1;
    if (s[510] != 0x55 || s[511] != 0xAA)                      return -2;
    f->bps  = (unsigned)s[0x0B] | ((unsigned)s[0x0C] << 8);
    f->spc  = s[0x0D];
    f->rsvd = (unsigned)s[0x0E] | ((unsigned)s[0x0F] << 8);
    f->nfats = s[0x10];
    if (f->bps < 512 || f->bps > 4096 || (f->bps & (f->bps - 1))
        || !f->spc || (f->spc & (f->spc - 1)) || f->spc > 128
        || !f->rsvd || f->nfats < 1 || f->nfats > 2)
        return -3;
    if (ld32(s + 0x16) & 0xFFFFu)                              return -4; /* FATSz16 != 0 */
    f->fatsz     = ld32(s + 0x24);
    f->root_clus = ld32(s + 0x2C);
    if (!f->fatsz || f->root_clus < 2)                         return -5;
    tot = (uint32_t)((unsigned)s[0x13] | ((unsigned)s[0x14] << 8));
    if (!tot) tot = ld32(s + 0x20);

    /* The cluster count is the only bound on cluster numbers, so it must not
     * be allowed to underflow: an image declaring tot = 0 would otherwise
     * produce 0xFFFFFFE1 and every cluster number would pass the check. */
    sys = (uint64_t)f->rsvd + (uint64_t)f->nfats * f->fatsz;
    if (!tot || (uint64_t)tot <= sys)                          return -6;
    nc = (((uint64_t)tot - sys) / f->spc) + 2;
    if (nc > 0x0FFFFFF8u) nc = 0x0FFFFFF8u;
    f->nclus = (uint32_t)nc;

    f->fat_off  = base + (uint64_t)f->rsvd * f->bps;
    f->data_off = f->fat_off + (uint64_t)f->nfats * f->fatsz * f->bps;

    /* Hard ceiling: the volume the EPE header declares, and the declared
     * total sector count, whichever is smaller. Nothing is read past it. */
    f->vol_end = base + (uint64_t)tot * f->bps;
    if (vol_bytes && base + vol_bytes < f->vol_end)
        f->vol_end = base + vol_bytes;
    if (f->data_off >= f->vol_end)                             return -7;
    return 0;
}

static uint32_t fat32_next(const struct fat32 *f, uint32_t clus)
{
    uint8_t e[4];
    uint64_t at = f->fat_off + 4ULL * clus;
    if (at + 4 > f->vol_end)
        return 0x0FFFFFFF;
    if (pread(f->fd, e, 4, (off_t)at) != 4)
        return 0x0FFFFFFF;
    return ld32(e) & 0x0FFFFFFFu;
}

static uint64_t fat32_clus_off(const struct fat32 *f, uint32_t clus)
{
    return f->data_off + (uint64_t)(clus - 2) * f->spc * f->bps;
}

/* Read a whole cluster chain, capped so a corrupt FAT cannot eat all memory. */
static int fat32_read_chain(const struct fat32 *f, uint32_t clus,
                            uint8_t **out, size_t *outlen, size_t cap)
{
    size_t csz = (size_t)f->spc * f->bps, n = 0, alloc = 0;
    size_t maxit = cap / csz + 1, it = 0;
    uint8_t *buf = NULL;

    while (clus >= 2 && clus < 0x0FFFFFF8u && clus < f->nclus && n + csz <= cap) {
        uint64_t at = fat32_clus_off(f, clus);
        uint8_t *nb;

        /* A FAT that loops back on itself would otherwise spin until the cap;
         * bound the walk by how many clusters the cap can hold. */
        if (++it > maxit) { free(buf); return -1; }
        if (at + csz > f->vol_end) { free(buf); return -1; }

        if (n + csz > alloc) {                    /* grow geometrically */
            size_t want = alloc ? alloc * 2 : csz;
            if (want < n + csz) want = n + csz;
            if (want > cap + csz) want = cap + csz;
            if (!(nb = realloc(buf, want))) { free(buf); return -1; }
            alloc = want; buf = nb;
        }
        if (pread(f->fd, buf + n, csz, (off_t)at) != (ssize_t)csz) {
            free(buf); return -1;
        }
        n += csz;
        clus = fat32_next(f, clus);
    }
    *out = buf; *outlen = n;
    return buf ? 0 : -1;
}

static void sfn_to_name(const uint8_t *e, char *out)
{
    int i, k = 0;
    for (i = 0; i < 8 && e[i] != ' '; i++) out[k++] = (char)e[i];
    if (e[8] != ' ') {
        out[k++] = '.';
        for (i = 8; i < 11 && e[i] != ' '; i++) out[k++] = (char)e[i];
    }
    out[k] = 0;
}

static int ci_eq(const char *a, const char *b)
{
    while (*a && *b) {
        int ca = *a >= 'A' && *a <= 'Z' ? *a + 32 : *a;
        int cb = *b >= 'A' && *b <= 'Z' ? *b + 32 : *b;
        if (ca != cb) return 0;
        a++; b++;
    }
    return !*a && !*b;
}

/* Find one component in a directory blob. Returns the first cluster, sets
 * *size and *isdir. Matches the long name and the 8.3 name, case-insensitively. */
static uint32_t dir_lookup(const uint8_t *dir, size_t dlen, const char *want,
                           uint32_t *size, int *isdir)
{
    size_t i;
    char lfn[261];
    int have_lfn = 0;

    memset(lfn, 0, sizeof(lfn));
    for (i = 0; i + 32 <= dlen; i += 32) {
        const uint8_t *e = dir + i;
        char sfn[13];

        if (e[0] == 0x00) break;
        if (e[0] == 0xE5) { have_lfn = 0; memset(lfn, 0, sizeof(lfn)); continue; }

        if (e[11] == 0x0F) {                     /* long-name fragment */
            unsigned ord = e[0] & 0x3Fu, k, p;
            char frag[14];
            static const unsigned off[13] = {1,3,5,7,9,14,16,18,20,22,24,28,30};
            for (k = 0, p = 0; k < 13; k++) {
                unsigned c = (unsigned)e[off[k]] | ((unsigned)e[off[k] + 1] << 8);
                if (!c || c == 0xFFFF) break;
                frag[p++] = (c < 0x80) ? (char)c : '?';
            }
            frag[p] = 0;
            if (ord >= 1 && ord <= 20) {
                size_t at = (size_t)(ord - 1) * 13;
                if (at + p < sizeof(lfn)) {
                    memcpy(lfn + at, frag, p);
                    lfn[at + p] = 0;    /* always terminate: a fragment without
                                         * the 0x40 flag would otherwise leave
                                         * ci_eq reading stale stack bytes */
                    have_lfn = 1;
                }
            }
            continue;
        }
        if (e[11] & 0x08) { have_lfn = 0; memset(lfn, 0, sizeof(lfn)); continue; }  /* volume label */

        sfn_to_name(e, sfn);
        if (ci_eq(sfn, want) || (have_lfn && ci_eq(lfn, want))) {
            *size  = ld32(e + 0x1C);
            *isdir = (e[11] & 0x10) != 0;
            return ((uint32_t)((unsigned)e[0x15] << 8 | e[0x14]) << 16)
                 | (uint32_t)((unsigned)e[0x1B] << 8 | e[0x1A]);
        }
        have_lfn = 0; memset(lfn, 0, sizeof(lfn));
    }
    return 0;
}

/* Read "/System/AlgId.dat" & co. Backslashes are accepted too. */
static int fat32_read_file(const struct fat32 *f, const char *path,
                           uint8_t **out, size_t *outlen)
{
    char comp[256];
    const char *p = path;
    uint32_t clus = f->root_clus, size = 0;
    int isdir = 1;
    uint8_t *blob = NULL;
    size_t blen = 0;

    *out = NULL; *outlen = 0;
    while (*p == '/' || *p == '\\') p++;

    while (*p) {
        size_t k = 0;
        while (*p && *p != '/' && *p != '\\' && k < sizeof(comp) - 1)
            comp[k++] = *p++;
        comp[k] = 0;
        while (*p == '/' || *p == '\\') p++;

        if (!isdir) return -1;
        if (fat32_read_chain(f, clus, &blob, &blen, 16u << 20) != 0) return -1;
        clus = dir_lookup(blob, blen, comp, &size, &isdir);
        free(blob); blob = NULL;
        if (!clus) return -1;
    }
    if (isdir) return -1;
    if (fat32_read_chain(f, clus, &blob, &blen, 64u << 20) != 0) return -1;
    if (size < blen) blen = size;              /* trim the last cluster */
    *out = blob; *outlen = blen;
    return 0;
}

/* --------------------------------------------- LBA base recovery */
/*
 * A partition image does not carry its start LBA, and the firmware encrypts
 * with the ABSOLUTE LBA of the disk. Rather than guess, we compute it.
 *
 * In CBC only the FIRST block of a sector depends on the IV, and the IV is a
 * known function of the sector number. So given the ciphertext of a sector
 * whose first 16 plaintext bytes are known, the sector number falls out:
 *
 *   AES family:   X  = AES_ECB_Dec(K, C0)      = P0 xor IV
 *                 IV = X xor P0
 *                 T  = AES_ECB_Dec(K, IV)      = [n | n | n | n]
 *                 n  = T[0..3], and the other three dwords must match  <- 96
 *                                                       bits of verification
 *   RC5 family:   A', B' = rounds only, before the chaining xor
 *                 n = A' xor a0 , and (B' xor b0) must equal n xor D5E74364
 *
 * Known first 16 bytes, per filesystem:
 *   exFAT      sector 0: EB 76 90 "EXFAT   " then five zero bytes  (16/16)
 *   NTFS       sector 0: EB 52 90 "NTFS    " + BPB; only bytes/sector and
 *                        sectors/cluster vary, both from a short list
 *   FAT32      sector 1: the FSInfo sector, "RRaA" then twelve zero bytes
 */

struct known16 { uint8_t p[16]; unsigned sector; const char *what; };

static int build_candidates(const uint8_t *plain0, const uint8_t *plain1,
                            size_t n0, size_t n1,
                            struct known16 *out, int max)
{
    int n = 0;
    static const unsigned BPS[] = { 512, 1024, 2048, 4096 };
    static const unsigned SPC[] = { 1, 2, 4, 8, 16, 32, 64, 128 };
    unsigned a, b;

    /* exFAT - every one of the sixteen bytes is fixed by the spec. */
    if (n0 >= 512 && plain0[510] == 0x55 && plain0[511] == 0xAA && n < max) {
        static const uint8_t x[11] = { 0xEB,0x76,0x90,'E','X','F','A','T',' ',' ',' ' };
        memcpy(out[n].p, x, 11);
        memset(out[n].p + 11, 0, 5);
        out[n].sector = 0; out[n].what = "exFAT (boot sector)";
        n++;
    }
    /* NTFS - eleven fixed bytes, then bytes/sector and sectors/cluster. */
    if (n0 >= 512 && plain0[510] == 0x55 && plain0[511] == 0xAA) {
        static const uint8_t x[11] = { 0xEB,0x52,0x90,'N','T','F','S',' ',' ',' ',' ' };
        for (a = 0; a < 4 && n < max; a++)
            for (b = 0; b < 8 && n < max; b++) {
                memcpy(out[n].p, x, 11);
                out[n].p[11] = (uint8_t)(BPS[a] & 0xFF);
                out[n].p[12] = (uint8_t)(BPS[a] >> 8);
                out[n].p[13] = (uint8_t)SPC[b];
                out[n].p[14] = 0; out[n].p[15] = 0;
                out[n].sector = 0; out[n].what = "NTFS (boot sector)";
                n++;
            }
    }
    /* FAT32 - the FSInfo sector in sector 1 begins with a fixed signature
     * followed by reserved bytes the spec requires to be zero. */
    if (n1 >= 512 && plain1[0x1E4] == 'r' && plain1[0x1E5] == 'r'
        && plain1[0x1E6] == 'A' && plain1[0x1E7] == 'a'
        && plain1[510] == 0x55 && plain1[511] == 0xAA && n < max) {
        memcpy(out[n].p, "RRaA", 4);
        memset(out[n].p + 4, 0, 12);
        out[n].sector = 1; out[n].what = "FAT32 (FSInfo sector)";
        n++;
    }
    return n;
}

static int aes_ecb_dec_block(const uint8_t *in, uint8_t *out)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l = 0, rc = -1;
    if (!c) return -1;
    if (EVP_DecryptInit_ex(c, EVP_aes_256_ecb(), NULL, g.key, NULL) != 1) goto out;
    EVP_CIPHER_CTX_set_padding(c, 0);
    if (EVP_DecryptUpdate(c, out, &l, in, 16) != 1 || l != 16) goto out;
    rc = 0;
out:
    EVP_CIPHER_CTX_free(c);
    return rc;
}

/* Returns 0 and sets *base on success. */
static int recover_lba_base(uint64_t *base, const char **how)
{
    uint8_t c0[MAX_SECTOR + 16], c1[MAX_SECTOR + 16];
    uint8_t p0[MAX_SECTOR + 16], p1[MAX_SECTOR + 16];
    struct known16 cand[64];
    int ncand, i;
    uint64_t save = g.lba_base;

    if (g.size < 2ULL * g.sector) return -1;
    if (pread(g.fd, c0, g.sector, (off_t)g.offset) != (ssize_t)g.sector) return -1;
    if (pread(g.fd, c1, g.sector, (off_t)(g.offset + g.sector)) != (ssize_t)g.sector)
        return -1;

    /* Everything past byte 16 decrypts correctly whatever the base, which is
     * enough to tell which filesystem we are looking at. */
    g.lba_base = 0;
    if (decrypt_sector(0, c0, p0, g.sector) != 0
        || decrypt_sector(1, c1, p1, g.sector) != 0) { g.lba_base = save; return -1; }
    g.lba_base = save;

    ncand = build_candidates(p0, p1, g.sector, g.sector, cand, 64);
    if (!ncand) return -1;

    for (i = 0; i < ncand; i++) {
        const uint8_t *ct = cand[i].sector ? c1 : c0;
        uint32_t n;

        if (g.algid == ALG_AES256 || g.algid == ALG_SBAES256) {
            uint8_t x[16], iv[16], t[16];
            int k;
            if (aes_ecb_dec_block(ct, x) != 0) continue;
            for (k = 0; k < 16; k++) iv[k] = x[k] ^ cand[i].p[k];
            if (g.raw_iv) {
                memcpy(t, iv, 16);
            } else if (aes_ecb_dec_block(iv, t) != 0) continue;
            n = ld32(t);
            if (ld32(t + 4) != n || ld32(t + 8) != n || ld32(t + 12) != n)
                continue;                       /* 96 bits of verification */
        } else {
            uint32_t A, B;
            rc5_first_block_raw(g.rc5ctx, g.algid == ALG_RC5_12 ? 12 : 18,
                                ct, &A, &B);
            n = A ^ ld32(cand[i].p);
            if ((B ^ ld32(cand[i].p + 4)) != (n ^ RC5_MAGIC))
                continue;                       /* 32 bits of verification */
        }

        if (n < cand[i].sector) continue;
        *base = (uint64_t)n - cand[i].sector;
        *how  = cand[i].what;
        return 0;
    }
    return -1;
}

/* Same recovery, but sweeping the algorithm and the IV mode when the user has
 * not pinned them. A recovery that succeeds proves the variant too: the check
 * is 96 bits wide for AES, and for RC5 the wrong cipher simply never produces
 * the (n, n^D5E74364) relation. The winning variant stays installed in g. */
static int recover_lba_base_sweep(uint64_t *base, const char **how)
{
    int algs[NALGS], nalg = 0, ai, iv, sweep_iv;
    int save_alg = g.algid, save_iv = g.raw_iv;

    if (g.alg_given) algs[nalg++] = g.algid;
    else for (ai = 0; ai < NALGS; ai++) algs[nalg++] = ALGS[ai].id;

    for (ai = 0; ai < nalg; ai++) {
        g.algid = algs[ai];
        sweep_iv = (g.algid == ALG_AES256 || g.algid == ALG_SBAES256)
                   && !g.iv_given;
        for (iv = 0; iv <= (sweep_iv ? 1 : 0); iv++) {
            if (sweep_iv) g.raw_iv = iv;
            if (recover_lba_base(base, how) == 0)
                return 0;
        }
        g.raw_iv = save_iv;
    }
    g.algid = save_alg;
    g.raw_iv = save_iv;
    return -1;
}

/* ------------------------------------------------- product integrity */
/*
 * Recovered from EpeBootcode.efi. These are the checks the firmware itself
 * performs; reproducing them lets us prove, before touching anything, that
 * we are looking at a real EPE volume rather than at a wrong offset.
 *
 *   EPE_calc_sector_checksum        @0x1005BC35
 *   EPE_calculate_trailing_checksum @0x1005BC53
 *   EPEEFI_gpt_disk_handler::get_valid_epe_header @0x10062446
 *   EPEEFI_utils::crc32             @0x10137E20   (standard reflected CRC-32)
 *
 * The metadata sectors - EPE partition header, disk state info, power-fail
 * header, MBR chain sector - carry their checksum in the last dword, computed
 * so that the whole 512-byte sector sums to zero. Bulk data sectors carry
 * nothing: the disk encryption itself has no integrity whatsoever.
 */

#define EPE_HDR_MAGIC "EpeMacEpePartHDR"

static uint32_t epe_sector_checksum(const uint8_t sec[512])
{
    uint32_t sum = 0;
    int i;
    for (i = 0; i < 128; i++)
        sum = ld32(sec + 4 * i) + ((sum >> 1) | (sum << 31));   /* ROR32(sum,1) */
    return sum;
}

/* Store the value that makes the sector sum to zero, in the last dword. */
__attribute__((unused))
static void epe_set_trailing_checksum(uint8_t sec[512])
{
    st32(sec + 508, 0);
    st32(sec + 508, (uint32_t)(0u - epe_sector_checksum(sec)));
}

static uint32_t epe_crc32(uint32_t seed, const uint8_t *p, size_t n)
{
    uint32_t c = ~seed;
    size_t i;
    unsigned k;
    for (i = 0; i < n; i++) {
        c ^= p[i];
        for (k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(c & 1)));
    }
    return ~c;
}

/* The firmware's own validity test for the EPE partition header sector,
 * transcribed from get_valid_epe_header. */
static int epe_header_valid(const uint8_t sec[512], const char **why)
{
    if (memcmp(sec, EPE_HDR_MAGIC, 16) != 0) { *why = "EpeMacEpePartHDR signature missing"; return 0; }
    if (epe_sector_checksum(sec) != 0)       { *why = "sector checksum is not zero"; return 0; }
    if (ld32(sec + 0x1C) == 0)               { *why = "field +0x1C is zero"; return 0; }
    if (ld32(sec + 0x28) <= 2)               { *why = "field +0x28 <= 2"; return 0; }
    *why = NULL;
    return 1;
}

/* ------------------------------------------------------ mode automatique */
/*
 * Given the Trellix partition (McAfeeEpeReserved) and the PPK, work out
 * everything else: locate the PBFS, read AlgId.dat and SystemKey.dat out of
 * it, decide which autoboot variant is in use, derive the disk key, and prove
 * the PPK is right by replaying the firmware's own key check on AbSecPol.dat.
 */

/* AES-256-CBC with IV = E(K, 0^16), PKCS#7 - MCC_crypto_sym_encryptor. */
static int absecpol_decrypt(const uint8_t ppk[KEY_LEN], const uint8_t *ct,
                            size_t ctlen, uint8_t *out, size_t *outlen)
{
    uint8_t zero[16] = { 0 }, iv[16];
    EVP_CIPHER_CTX *c;
    int l = 0, rc = -1;

    if (!ctlen || ctlen % 16) return -1;
    if (!(c = EVP_CIPHER_CTX_new())) return -1;
    if (EVP_EncryptInit_ex(c, EVP_aes_256_ecb(), NULL, ppk, NULL) != 1) goto out;
    EVP_CIPHER_CTX_set_padding(c, 0);
    if (EVP_EncryptUpdate(c, iv, &l, zero, 16) != 1) goto out;
    if (EVP_CIPHER_CTX_reset(c) != 1) goto out;
    if (EVP_DecryptInit_ex(c, EVP_aes_256_cbc(), NULL, ppk, iv) != 1) goto out;
    EVP_CIPHER_CTX_set_padding(c, 0);
    if (EVP_DecryptUpdate(c, out, &l, ct, (int)ctlen) != 1) goto out;
    *outlen = (size_t)l;
    if (*outlen) {                                   /* strip PKCS#7 */
        unsigned pad = out[*outlen - 1];
        if (pad >= 1 && pad <= 16 && *outlen >= pad) *outlen -= pad;
    }
    rc = 0;
out:
    EVP_CIPHER_CTX_free(c);
    return rc;
}

/* EPE_system_autoboot::load_key_secure requires bytes 3..511 to be zero. */
static int absecpol_keycheck(const uint8_t *plain, size_t n)
{
    size_t i;
    if (n < 512) return 0;
    for (i = 3; i < 512; i++) if (plain[i]) return 0;
    return 1;
}

/* Start LBA of a partition block device, straight from sysfs. */
static int part_start_lba(const char *path, uint64_t *lba)
{
    char p[128];
    struct stat st;
    FILE *f;
    unsigned long long v;

    if (stat(path, &st) != 0 || !S_ISBLK(st.st_mode)) return -1;
    snprintf(p, sizeof(p), "/sys/dev/block/%u:%u/start",
             (unsigned)major(st.st_rdev), (unsigned)minor(st.st_rdev));
    if (!(f = fopen(p, "r"))) return -1;
    if (fscanf(f, "%llu", &v) != 1) { fclose(f); return -1; }
    fclose(f);
    *lba = (uint64_t)v;
    return 0;
}

struct autoresult { int ok; int algid; uint8_t key[KEY_LEN]; };

static uint64_t file_size(int fd);

/*
 * Locating the PBFS inside the Trellix partition.
 *
 * Field +0x2C of the EPE header was recovered by static analysis, and it does
 * not behave as a start LBA everywhere: on at least one fleet it holds
 * start + size, i.e. the END LBA. Rather than bet on one interpretation, we
 * try the plausible candidates, and - if none holds - we look for the FAT32
 * VBR by scanning. The volume is an ordinary FAT32 (EPE_create_fat32_pbfs),
 * so its boot sector is recognisable without trusting the header at all.
 */
static int looks_like_fat32_vbr(const uint8_t *s)
{
    unsigned bps, rsvd;
    uint8_t spc, nfats;

    if (s[510] != 0x55 || s[511] != 0xAA)            return 0;
    if (s[0] != 0xEB && s[0] != 0xE9)                return 0;   /* jump */
    bps = (unsigned)s[0x0B] | ((unsigned)s[0x0C] << 8);
    if (bps != 512 && bps != 1024 && bps != 2048 && bps != 4096) return 0;
    spc = s[0x0D];
    if (!spc || (spc & (spc - 1)) || spc > 128)      return 0;
    rsvd = (unsigned)s[0x0E] | ((unsigned)s[0x0F] << 8);
    if (!rsvd)                                       return 0;
    nfats = s[0x10];
    if (nfats < 1 || nfats > 2)                      return 0;
    /* FAT32: root entry count zero, FATSz16 zero, FATSz32 non-zero. */
    if ((unsigned)s[0x11] | ((unsigned)s[0x12] << 8)) return 0;
    if ((unsigned)s[0x16] | ((unsigned)s[0x17] << 8)) return 0;
    if (!ld32(s + 0x24))                             return 0;
    return 1;
}

/* Scan [start, end) and return the absolute offset of the first FAT32 VBR, or 0. */
static uint64_t pbfs_scan_vbr(int fd, uint64_t start, uint64_t end)
{
    enum { CHUNK = 1u << 20 };
    uint8_t *buf = malloc(CHUNK);
    uint64_t off;

    if (!buf) return 0;
    for (off = start; off < end; off += CHUNK) {
        size_t want = (size_t)((end - off < CHUNK) ? (end - off) : CHUNK);
        ssize_t got = pread(fd, buf, want, (off_t)off);
        size_t k;
        if (got < 512) break;
        for (k = 0; k + 512 <= (size_t)got; k += 512) {
            if (looks_like_fat32_vbr(buf + k)) {
                uint64_t hit = off + k;
                free(buf);
                return hit;
            }
        }
    }
    free(buf);
    return 0;
}

static void dump_hdr(const uint8_t *h, size_t n)
{
    size_t i, j;
    fprintf(stderr, "\n  EPE header, first %zu bytes:\n", n);
    for (i = 0; i < n; i += 16) {
        fprintf(stderr, "    %04zx  ", i);
        for (j = 0; j < 16; j++) fprintf(stderr, "%02x ", h[i + j]);
        fprintf(stderr, " |");
        for (j = 0; j < 16; j++) {
            uint8_t c = h[i + j];
            fputc((c >= 32 && c < 127) ? c : '.', stderr);
        }
        fprintf(stderr, "|\n");
    }
    fprintf(stderr, "\n");
}

static struct autoresult auto_from_trellix(const char *tpath, uint64_t toff,
                                           const uint8_t *ppk, int have_ppk,
                                           uint64_t pbfs_forced)
{
    struct autoresult r; 
    struct fat32 fs;
    uint8_t hdr[512], *blob = NULL, *sk = NULL, *abs = NULL;
    size_t blen = 0, sklen = 0, abslen = 0;
    const char *why = NULL;
    int64_t pbfs_lba;
    uint32_t pbfs_sec;
    int tfd, secure = 0, i, rc;

    memset(&r, 0, sizeof(r));

    {   struct stat st;
        if ((tfd = open(tpath, O_RDONLY | O_LARGEFILE | O_NONBLOCK)) < 0) {
            perror(tpath); return r;
        }
        if (fstat(tfd, &st) != 0 || !(S_ISREG(st.st_mode) || S_ISBLK(st.st_mode))) {
            fprintf(stderr, "%s: neither a regular file nor a block device\n",
                    tpath);
            close(tfd); return r;
        }
    }

    if (pread(tfd, hdr, 512, (off_t)toff) != 512) {
        fprintf(stderr, "%s: header unreadable at offset %llu\n",
                tpath, (unsigned long long)toff);
        close(tfd); return r;
    }
    if (!epe_header_valid(hdr, &why)) {
        fprintf(stderr,
            "%s: not a valid Trellix/McAfee partition (%s).\n"
            "  Expected: a partition of type GUID 38EDAEA1-E0D5-4888-A970-8E03E60BF06A\n"
            "  named McAfeeEpeReserved, whose first sector carries EpeMacEpePartHDR.\n",
            tpath, why);
        close(tfd); return r;
    }
    pbfs_lba = (int64_t)((uint64_t)ld32(hdr + 0x2C) | ((uint64_t)ld32(hdr + 0x30) << 32));
    pbfs_sec = ld32(hdr + 0x34);
    if (pbfs_lba < 0
        || (uint64_t)pbfs_lba > (uint64_t)(INT64_MAX - (int64_t)toff) / 512)
        pbfs_lba = 0;
    fprintf(stderr, "trellix   : EPE header valid, PBFS at LBA %lld over %u sectors\n",
            (long long)pbfs_lba, pbfs_sec);

    /* ---- locating the PBFS -------------------------------------------- */
    {
        uint64_t cand[6], base = 0, tsize = file_size(tfd);
        const char *how = NULL, *hows[6];
        int nc = 0, k, ok = 0;

        if (pbfs_forced) {
            cand[nc] = pbfs_forced; hows[nc++] = "--pbfs-lba";
        } else {
            if (pbfs_lba > 0) {
                cand[nc] = (uint64_t)pbfs_lba;
                hows[nc++] = "field +0x2C read as start LBA";
                /* Fallback hypothesis: +0x2C holds the END LBA, in which
                 * case the start is end - size. That is what gives
                 * 102432 - 102400 = 32 on a real fleet. */
                if ((uint64_t)pbfs_lba > (uint64_t)pbfs_sec) {
                    cand[nc] = (uint64_t)pbfs_lba - (uint64_t)pbfs_sec;
                    hows[nc++] = "field +0x2C read as END LBA (start = end - size)";
                }
            }
            cand[nc] = 32; hows[nc++] = "LBA 32 (usual value)";
            cand[nc] = 1;  hows[nc++] = "LBA 1";
        }

        for (k = 0; k < nc && !ok; k++) {
            uint64_t b = toff + cand[k] * 512;
            if (tsize && b + 512 > tsize) continue;
            if (fat32_open(&fs, tfd, b, (uint64_t)pbfs_sec * 512) == 0) {
                base = cand[k]; how = hows[k]; ok = 1;
            }
        }

        /* Nothing held: look for the boot sector ourselves. */
        if (!ok && !pbfs_forced) {
            uint64_t hit;
            fprintf(stderr, "PBFS      : no LBA derived from the header carries a "
                            "FAT32 VBR.\n            Scanning the partition...\n");
            hit = pbfs_scan_vbr(tfd, toff, tsize ? tsize : toff + (1ull << 30));
            if (hit && fat32_open(&fs, tfd, hit, 0) == 0) {
                base = (hit - toff) / 512;
                how = "scan: FAT32 VBR found";
                ok = 1;
            }
        }

        if (!ok) {
            fprintf(stderr,
                "PBFS      : no FAT32 volume found in %s.\n"
                "\n"
                "  The EPE header is valid, so this really is the Trellix partition,\n"
                "  but the preboot filesystem is not where the header fields say it\n"
                "  is, and no FAT32 VBR was found by scanning. Two possibilities:\n"
                "    - --trellix points at a PARTITION while the header LBA is\n"
                "      absolute to the disk: retry with the whole disk and\n"
                "      --trellix-offset <partition start in bytes>\n"
                "    - the layout differs on this product version: pass\n"
                "      --pbfs-lba N, or extract the files by hand\n"
                "      (pbfs_locate.py) and pass --algid-file / --systemkey\n", tpath);
            dump_hdr(hdr, 0x60);
            close(tfd); return r;
        }
        if (base != (uint64_t)pbfs_lba)
            fprintf(stderr, "PBFS      : located at LBA %llu (%s)\n",
                    (unsigned long long)base, how);
    }
    (void)rc;
    fprintf(stderr, "PBFS      : FAT32, %u bytes/sector, %u sectors/cluster\n",
            fs.bps, fs.spc);

    /* --- algorithme --- */
    if (fat32_read_file(&fs, "/System/AlgId.dat", &blob, &blen) == 0 && blen >= 4) {
        r.algid = (int)ld32(blob);
        fprintf(stderr, "AlgId.dat : %d (%s)\n", r.algid, alg_name(r.algid));
        if (r.algid != ALG_AES256 && r.algid != ALG_SBAES256
            && r.algid != ALG_RC5_12 && r.algid != ALG_RC5_18) {
            fprintf(stderr, "  unknown algorithm - nothing to be done with this volume\n");
            free(blob); close(tfd); return r;
        }
    } else {
        r.algid = ALG_AES256;
        fprintf(stderr, "AlgId.dat : absent, assuming %d (%s)\n",
                r.algid, alg_name(r.algid));
    }
    free(blob); blob = NULL;

    /* --- which autoboot variant? --- */
    if (fat32_read_file(&fs, "/System/AbSecPol.dat", &abs, &abslen) == 0) {
        secure = 1;
        fprintf(stderr, "AbSecPol  : present (%zu bytes) -> secure variant\n", abslen);
        if (have_ppk) {
            uint8_t *plain = malloc(abslen + 32);
            size_t plen = 0;
            if (!plain) {
                fprintf(stderr, "PPK       : cannot verify (out of memory)\n");
            } else if (absecpol_decrypt(ppk, abs, abslen, plain, &plen) != 0) {
                fprintf(stderr, "PPK       : NOT VERIFIABLE - AbSecPol.dat is "
                                "%zu bytes, not a multiple of 16\n", abslen);
            } else if (absecpol_keycheck(plain, plen)) {
                fprintf(stderr, "PPK       : VALID (load_key_secure check: "
                                "bytes 3..511 are zero)\n");
            } else {
                /* On this variant the PPK does not enter the disk key at all,
                 * so a wrong one is a warning, not a reason to stop. */
                fprintf(stderr, "PPK       : REJECTED by the load_key_secure "
                                "check - the disk key does not depend on it "
                                "here, continuing\n");
            }
            free(plain);
        } else {
            fprintf(stderr, "PPK       : not supplied - the disk key does not depend "
                            "on it in this variant\n");
        }
    } else {
        fprintf(stderr, "AbSecPol  : absent -> legacy variant (XOR)\n");
    }
    free(abs);

    /* --- the key --- */
    if (fat32_read_file(&fs, "/System/SystemKey.dat", &sk, &sklen) != 0) {
        fprintf(stderr, "SystemKey.dat not found in the PBFS\n");
        close(tfd); return r;
    }
    fprintf(stderr, "SystemKey : %zu bytes\n", sklen);
    if (sklen < KEY_LEN) {
        fprintf(stderr, "  too short for a %d-byte key\n", KEY_LEN);
        free(sk); close(tfd); return r;
    }
    memcpy(r.key, sk, KEY_LEN);
    free(sk);

    if (!secure) {
        if (!have_ppk) {
            fprintf(stderr, "  the legacy variant requires --ppk\n");
            close(tfd); return r;
        }
        for (i = 0; i < KEY_LEN; i++) r.key[i] ^= ppk[i];
        fprintf(stderr, "disk key  : SystemKey.dat XOR PPK\n");
    } else {
        fprintf(stderr, "disk key  : SystemKey.dat verbatim\n");
    }

    close(tfd);
    r.ok = 1;
    return r;
}

/* ---------------------------------------------------------------- utils */

static int unhex(const char *hex, uint8_t *out, size_t want)
{
    size_t n = 0;
    while (*hex && n < want) {
        int hi, lo;
        while (*hex == ' ' || *hex == ':') hex++;
        if (!hex[0] || !hex[1]) return -1;
        hi = (hex[0] >= '0' && hex[0] <= '9') ? hex[0] - '0'
           : (hex[0] | 32) >= 'a' && (hex[0] | 32) <= 'f' ? (hex[0] | 32) - 'a' + 10 : -1;
        lo = (hex[1] >= '0' && hex[1] <= '9') ? hex[1] - '0'
           : (hex[1] | 32) >= 'a' && (hex[1] | 32) <= 'f' ? (hex[1] | 32) - 'a' + 10 : -1;
        if (hi < 0 || lo < 0) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    while (*hex == ' ' || *hex == '\n' || *hex == '\r') hex++;
    return (n == want && *hex == 0) ? 0 : -1;
}

static int read_file(const char *path, uint8_t *out, size_t want)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    if (!f) { perror(path); return -1; }
    n = fread(out, 1, want, f);
    fclose(f);
    if (n != want) {
        fprintf(stderr, "%s: read %zu bytes, expected %zu\n", path, n, want);
        return -1;
    }
    return 0;
}

static uint64_t file_size(int fd)
{
    struct stat st;
    off_t end;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode))
        return (uint64_t)st.st_size;
    end = lseek(fd, 0, SEEK_END);          /* block device */
    return end > 0 ? (uint64_t)end : 0;
}

/* --------------------------------------------------------------- probe */

/* Recognisable signatures in a freshly decrypted region.
 *
 * Crucial subtlety: in CBC, a wrong IV corrupts ONLY the first 16 bytes of the
 * sector - everything after it decrypts correctly. So a signature living past
 * byte 16 (FAT32's "FAT32   " at 0x52, the 55AA at 0x1FE, ext's magic at
 * 0x438) proves the KEY is right but says nothing about the sector numbering.
 * Only a signature inside the first block can confirm --lba-base, and getting
 * the base wrong silently mangles 16 bytes of every single sector. */
struct ident { const char *name; int confirms_base; };
#define g_sector_hint ((size_t)g.sector)

static int printable(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        if (p[i] < 0x20 || p[i] > 0x7E)
            return 0;
    return 1;
}

static struct ident identify(const uint8_t *b, size_t n)
{
    struct ident r = { NULL, 0 };
    size_t s1 = g_sector_hint;               /* start of sector 1 */

    /* ------------------------------------------------------------------
     * confirms_base = 1 is reserved for signatures that pin down EVERY byte
     * of the first cipher block of a sector - sixteen bytes for the AES
     * family, eight for RC5. Nothing weaker will do, and the RC5 family is
     * why: its "IV" is not a cipher but a plain XOR of (n, n ^ D5E74364)
     * into the first block. A wrong sector number therefore does not
     * randomise those bytes, it merely XORs them with (n_true ^ n_wrong).
     * A boot sector decrypted one sector off still reads EB 5A 80 "NTNC" -
     * jump byte intact, OEM field still printable, 55AA still in place. Any
     * heuristic ("starts with EB, OEM looks like ASCII") is passed by
     * construction. Only an exact, fully known first block rules the base in.
     * ------------------------------------------------------------------ */

    /* NTFS boot sector: EB 52 90 "NTFS    " covers bytes 0..10. */
    if (n >= 512 && b[0] == 0xEB && b[1] == 0x52 && b[2] == 0x90
        && !memcmp(b + 3, "NTFS    ", 8)) {
        r.name = "NTFS"; r.confirms_base = 1; return r;
    }
    /* exFAT boot sector: EB 76 90 "EXFAT   " then five bytes the spec
     * requires to be zero - bytes 0..15, the whole AES block. */
    if (n >= 512 && b[0] == 0xEB && b[1] == 0x76 && b[2] == 0x90
        && !memcmp(b + 3, "EXFAT   ", 8)
        && !b[11] && !b[12] && !b[13] && !b[14] && !b[15]) {
        r.name = "exFAT"; r.confirms_base = 1; return r;
    }
    /* FAT32: the boot sector's OEM name is arbitrary, so it can never pin
     * the base. The FSInfo sector that follows it can: "RRaA" then twelve
     * reserved bytes that must be zero, and "rrAa" at 0x1E4 to prove we are
     * really looking at FSInfo and not at a lucky coincidence. */
    if (n >= s1 + 512 && !memcmp(b + s1, "RRaA", 4)
        && !memcmp(b + s1 + 4, "\0\0\0\0\0\0\0\0\0\0\0\0", 12)
        && !memcmp(b + s1 + 0x1E4, "rrAa", 4)
        && b[s1 + 510] == 0x55 && b[s1 + 511] == 0xAA) {
        r.name = "FAT32"; r.confirms_base = 1; return r;
    }
    /* GPT: "EFI PART" is bytes 0..7 of sector 1 - exactly one RC5 block,
     * and the eight bytes that follow are the revision and header size,
     * fixed at 00 00 01 00 5C 00 00 00 for every GPT ever written. */
    if (n >= s1 + 16 && !memcmp(b + s1, "EFI PART", 8)
        && !memcmp(b + s1 + 8, "\x00\x00\x01\x00\x5C\x00\x00\x00", 8)) {
        r.name = "en-tete GPT"; r.confirms_base = 1; return r;
    }
    /* LUKS: the magic covers bytes 0..5 and the version dword follows; any
     * nonzero XOR difference lands inside it. */
    if (n >= 512 && !memcmp(b, "LUKS\xba\xbe", 6)
        && b[6] == 0x00 && (b[7] == 0x01 || b[7] == 0x02)) {
        r.name = "LUKS"; r.confirms_base = 1; return r;
    }

    /* --- everything below proves only that the KEY is right --- */
    if (n >= 0x43A && b[0x438] == 0x53 && b[0x439] == 0xEF) {
        r.name = "ext2/3/4"; return r;
    }
    if (n > 0x5A && !memcmp(b + 0x52, "FAT32   ", 8)) { r.name = "FAT32"; return r; }
    if (n > 0x3A && !memcmp(b + 0x36, "FAT", 3))      { r.name = "FAT12/16"; return r; }
    if (n >= 512 && (b[0] == 0xEB || b[0] == 0xE9) && printable(b + 3, 8)
        && b[510] == 0x55 && b[511] == 0xAA) {
        r.name = "boot sector (jump + ASCII OEM)"; return r;
    }
    if (n >= 512 && b[510] == 0x55 && b[511] == 0xAA) {
        r.name = "boot sector (55AA only)"; return r;
    }
    return r;
}

/* --find-lba : recover the absolute sector number of the first sector, instead
 * of guessing it. Made for the case where the encrypted volume is a *partition
 * image*: such an image carries no absolute LBA anywhere, yet the cipher needs
 * it, because the IV of sector n is a known function of n. See the comment
 * above recover_lba_base for the algebra. */
static int do_find_lba(void)
{
    uint64_t base = 0;
    const char *how = NULL;
    uint8_t *buf;
    size_t span = 128 * 1024;
    int confirmed = 0;
    const char *fsname = NULL;

    printf("analytic LBA base recovery\n"
           "  the IV of sector n is a known function of n, and in CBC only the\n"
           "  first block depends on it: 16 bytes of known plaintext are therefore\n"
           "  enough to recover n, with no scanning.\n\n");

    if (recover_lba_base_sweep(&base, &how) != 0) {
        printf("  failed.\n\n"
               "  The start of the region must carry a recognised filesystem\n"
               "  (NTFS, exFAT or FAT32) and the key must be correct.\n"
               "  Run --probe: it will tell you whether the key and the algorithm\n"
               "  hold.\n");
        return 1;
    }

    /* Independent confirmation: mount-grade check on the recovered base. */
    if (span > g.size) span = (size_t)g.size;
    if ((buf = malloc(span)) != NULL) {
        uint64_t save = g.lba_base;
        ssize_t got;
        g.lba_base = base;
        got = read_plain(buf, span, 0);
        if (got > 0) {
            struct ident id = identify(buf, (size_t)got);
            fsname = id.name;
            confirmed = id.confirms_base;
        }
        g.lba_base = save;
        free(buf);
    }

    printf("  anchor    : %s\n", how);
    printf("  algorithm : %s (id %d)%s\n", alg_name(g.algid), g.algid,
           (g.algid == ALG_AES256 || g.algid == ALG_SBAES256)
               ? (g.raw_iv ? ", raw IV" : ", encrypted IV") : "");
    printf("  LBA base  : %llu   (the first sector of the region is sector "
           "%llu of the original disk)\n",
           (unsigned long long)base, (unsigned long long)base);
    printf("  check     : %s%s\n\n",
           fsname ? fsname : "no signature read back",
           confirmed ? ", base confirmed" : " - NOT confirmed, be careful");

    printf("  -> mount with --lba-base %llu --algid %d%s\n",
           (unsigned long long)base, g.algid,
           (g.raw_iv && (g.algid == ALG_AES256 || g.algid == ALG_SBAES256))
               ? " --raw-iv" : "");
    printf("     (mounting recovers it on its own: this option only exists so\n"
           "      you can record the value in a report or reuse it as is)\n");
    return confirmed ? 0 : 1;
}

static int do_probe(void)
{
    /* The firmware passes an absolute LBA; if the dump starts partway into
     * the disk, the base differs from zero. Try the plausible ones. */
    uint64_t cands[4];
    unsigned ncand = 0, k;
    int any_key_ok = 0, ai, sweep_alg = !g.alg_given, sweep_iv, iv;
    int algs[NALGS], nalg = 0;
    size_t span = 128 * 1024;                 /* enough for an ext superblock */
    uint8_t *buf;

    cands[ncand++] = g.lba_base;
    if (g.lba_base != 0)                  cands[ncand++] = 0;
    if (g.offset / g.sector != g.lba_base) cands[ncand++] = g.offset / g.sector;

    if (sweep_alg) { for (ai = 0; ai < NALGS; ai++) algs[nalg++] = ALGS[ai].id; }
    else           { algs[nalg++] = g.algid; }

    if (span > g.size) span = (size_t)g.size;
    if (!(buf = malloc(span))) { perror("malloc"); return 1; }

    printf("probe: %d algorithm(s) x %u LBA base(s), %zu KiB decrypted per try\n\n",
           nalg, ncand, span / 1024);

    for (ai = 0; ai < nalg; ai++) {
    int save_alg = g.algid;
    g.algid = algs[ai];
    sweep_iv = (g.algid == ALG_AES256 || g.algid == ALG_SBAES256) && !g.iv_given;
    for (iv = 0; iv <= (sweep_iv ? 1 : 0); iv++) {
    int save_iv = g.raw_iv;
    if (sweep_iv) g.raw_iv = iv;
    printf("  [%s%s]\n", alg_name(g.algid),
           (g.algid == ALG_AES256 || g.algid == ALG_SBAES256)
               ? (g.raw_iv ? ", raw IV" : ", encrypted IV") : "");
    for (k = 0; k < ncand; k++) {
        struct ident id;
        uint64_t save = g.lba_base;
        ssize_t got;

        g.lba_base = cands[k];
        got = read_plain(buf, span, 0);
        g.lba_base = save;

        if (got <= 0) { printf("      LBA base %-11llu  unreadable\n",
                               (unsigned long long)cands[k]); continue; }

        id = identify(buf, (size_t)got);
        printf("      LBA base %-11llu  %-34s %s\n",
               (unsigned long long)cands[k],
               id.name ? id.name : "nothing recognisable",
               id.name ? (id.confirms_base ? "[base confirmed]"
                                           : "[key ok, base NOT confirmed]")
                       : "");
        if (id.name && id.confirms_base) {
            printf("\n  -> mount with --algid %d%s --lba-base %llu\n",
                   g.algid,
                   (g.raw_iv && (g.algid == ALG_AES256 || g.algid == ALG_SBAES256))
                       ? " --raw-iv" : "",
                   (unsigned long long)cands[k]);
            free(buf);
            return 0;
        }
        if (id.name) any_key_ok = 1;
    }
    if (sweep_iv) g.raw_iv = save_iv;
    }
    g.algid = save_alg;
    }

    if (any_key_ok) {
        printf("\nThe disk key is correct - a signature was recognised beyond the\n"
               "16th byte. But no tested LBA base is confirmed, and in CBC a wrong\n"
               "base corrupts ONLY the first 16 bytes of each sector: the filesystem\n"
               "will appear to mount while every sector is silently altered.\n"
               "Find the real base: if --disk is an extracted partition, it is that\n"
               "partition's start LBA on the disk (fdisk -l, gdisk -l), to be passed\n"
               "as --lba-base. Do not mount anything until the base is confirmed.\n");
        free(buf);
        return 1;
    }

    printf("\nno signature found. In order of likelihood:\n"
           "  * the disk key is wrong (check it with absecpol_decrypt.py)\n"
           "  * --offset does not land on the start of the encrypted region\n"
           "  * the real LBA base is yet another one: --lba-base <n>\n"
           "  * AlgId.dat does not name AES (RC5-12, RC5-18 and SafeBoot AES\n"
           "    also exist and are implemented here too - try --probe)\n"
           "  * the region is only partially encrypted (conversion in progress)\n");
    free(buf);
    return 1;
}

static int do_dump(const char *path)
{
    FILE *out = fopen(path, "wb");
    uint8_t *buf;
    uint64_t pos = 0;
    int bad = 0;
    const size_t chunk = 4 << 20;

    if (!out) { perror(path); return 1; }
    if (!(buf = malloc(chunk))) { perror("malloc"); fclose(out); return 1; }

    while (pos < g.size) {
        size_t want = (g.size - pos > chunk) ? chunk : (size_t)(g.size - pos);
        ssize_t got = read_plain(buf, want, pos);
        if (got <= 0) { fprintf(stderr, "\nread interrupted at %llu\n",
                                (unsigned long long)pos); bad = 1; break; }
        if (fwrite(buf, 1, (size_t)got, out) != (size_t)got) {
            perror("write"); bad = 1; break;
        }
        pos += (uint64_t)got;
        fprintf(stderr, "\r  %llu / %llu MiB",
                (unsigned long long)(pos >> 20), (unsigned long long)(g.size >> 20));
    }
    fprintf(stderr, "\n");
    free(buf);
    if (fclose(out) != 0) { perror(path); bad = 1; }
    if (bad) { fprintf(stderr, "incomplete dump: %s\n", path); return 1; }
    printf("written: %s\n", path);
    return 0;
}

/* ----------------------------------------------------------------- main */

/* Frees on every return path out of main, including the error ones. */
static void free_ptr(void *p) { free(*(void **)p); }

static void usage(const char *me)
{
    fprintf(stderr,
"trellix-fuse - expose a Trellix/McAfee Drive Encryption volume in the clear\n"
"\n"
"  %s [options] <mountpoint>\n"
"  %s [options] --dump <file.img>\n"
"  %s [options] --probe\n"
"  %s [options] --find-lba\n"
"\n"
"Disk\n"
"  --disk PATH          encrypted partition, or an image of it\n"
"  --offset BYTES       start of the encrypted region inside --disk (default 0)\n"
"  --size BYTES         size of the region (default: to the end)\n"
"  --lba-base N         sector number of the region's first sector.\n"
"                       The firmware encrypts with the disk's ABSOLUTE LBA:\n"
"                       if --disk is a partition image, this is that\n"
"                       partition's start LBA. Default: --offset / sector size.\n"
"                       Rarely needed: the pre-mount check reconstructs it on\n"
"                       its own (see --find-lba).\n"
"  --sector-size N      512 by default\n"
"\n"
"Algorithm\n"
"  --algid N            18 AES-256-CBC (default), 17 SBAES-256-CBC,\n"
"                       0 RC5-12, 1 RC5-18\n"
"  --algid-file PATH    \\System\\AlgId.dat: read the identifier directly\n"
"  --raw-iv             AES family: use the raw sector-number block as the IV\n"
"                       instead of its encryption. Only worth trying if the\n"
"                       probe fails in the default mode.\n"
"  --list-algs          list the algorithms and how each builds its IV\n"
"\n"
"Disk image\n"
"  --image PATH         image of a WHOLE disk (or a device). The tool reads\n"
"                       the GPT or MBR table, finds the Trellix partition by\n"
"                       its type GUID, picks the encrypted partition and\n"
"                       derives offset, size and LBA base from it.\n"
"                       A bare PARTITION image goes to --disk instead.\n"
"  --part N             1-based index of the partition to decrypt.\n"
"                       Default: the largest one that is neither Trellix\n"
"                       nor the ESP.\n"
"  --list-parts         print the partition table and exit\n"
"\n"
"Automatic mode\n"
"  --trellix PATH       Trellix/McAfee partition (McAfeeEpeReserved). The tool\n"
"                       validates the EPE header, mounts the FAT32 PBFS\n"
"                       internally, reads AlgId.dat and SystemKey.dat, detects\n"
"                       the autoboot variant from AbSecPol.dat, derives the\n"
"                       disk key, and checks the PPK with the firmware's own\n"
"                       test. If --disk is a partition, its start LBA is read\n"
"                       from sysfs: nothing else to specify.\n"
"  --trellix-offset N   offset of the EPE header inside PATH (default 0)\n"
"  --pbfs-lba N         force the LBA of the FAT32 preboot volume inside the\n"
"                       Trellix partition. Normally unnecessary: the tool\n"
"                       derives it from the header, tries the possible\n"
"                       readings of field +0x2C, then scans for the FAT32 VBR.\n"
"                       Use this if all three fail.\n"
"\n"
"Key\n"
"  --key HEX            disk key, 64 hex characters (32 bytes)\n"
"  --ppk HEX            PPK captured on the SPI bus, 64 hex characters\n"
"  --ppk-file PATH      same, in binary\n"
"  --systemkey PATH     \\System\\SystemKey.dat extracted from the PBFS.\n"
"                       Combined with --ppk, gives the key by XOR.\n"
"  --secure             secure variant: SystemKey.dat is already the key,\n"
"                       no XOR is applied\n"
"\n"
"Writing\n"
"  --rw                 mount read-write. The disk is opened O_RDWR and writes\n"
"                       are re-encrypted sector by sector (read-modify-write\n"
"                       for unaligned writes). Refuses to mount unless the LBA\n"
"                       base is confirmed by a first-block signature.\n"
"  --force-lba          override that refusal. At your own risk.\n"
"  --force-header       override an invalid --epe-header.\n"
"  --force              both at once.\n"
"\n"
"Integrity\n"
"  --epe-header PATH    verify the EPE partition header before mounting:\n"
"                       EpeMacEpePartHDR signature, sector checksum zero,\n"
"                       fields +0x1C and +0x28 - exactly the firmware's\n"
"                       get_valid_epe_header test.\n"
"  --epe-offset N       offset of that sector inside PATH (default 0)\n"
"  --check-sector PATH  verify one EPE metadata sector and exit\n"
"  --verify-writes      after each write, read the sector back, decrypt it and\n"
"                       require a match. Catches a failing disk or transport.\n"
"                       Does NOT catch a wrong LBA base: the read-back uses the\n"
"                       same sector number the write used, so it round-trips.\n"
"                       Only the mount-time check covers that case.\n"
"\n"
"Modes\n"
"  --probe              mount nothing: sweep algorithms and LBA bases\n"
"  --find-lba           mount nothing: COMPUTE the LBA base instead of\n"
"                       searching for it. In CBC only a sector's first block\n"
"                       depends on the IV, and the IV of sector n is a known\n"
"                       function of n: 16 bytes of known plaintext (NTFS,\n"
"                       exFAT or FAT32) are enough to invert n. Useful when the\n"
"                       encrypted region is a PARTITION image, which carries no\n"
"                       absolute LBA anywhere. Mounting does this by itself;\n"
"                       this option only exists to read the value out.\n"
"  --dump FILE          write the whole decrypted region to a file\n"
"  --name NAME          name of the virtual file (default: trellix-disk)\n"
"\n"
"Without --rw the mount is read-only. The usual FUSE options go after the\n"
"mountpoint: -f (foreground), -o allow_other, -s (single-threaded).\n"
"\n"
"Examples\n"
"  trellix-fuse --image disk.dd --ppk <64 hex> /mnt/epe\n"
"  trellix-fuse --image disk.dd --list-parts\n"
"\n"
"  trellix-fuse --disk /dev/sda3 --trellix /dev/sda4 --ppk <64 hex> /mnt/epe\n"
"  mount -o loop,ro /mnt/epe/trellix-disk /mnt/clear\n"
"\n""  # two partition images: the Trellix one and the encrypted one, nothing else\n"
"  trellix-fuse --disk encrypted.img --trellix trellix.img --ppk <64 hex> \\\n"
"               /mnt/epe\n"
"  trellix-fuse --disk encrypted.img --trellix trellix.img --ppk <64 hex> \\\n"
"               --find-lba\n"
"\n"
"  %s --disk /dev/sda3 --ppk 00112233... --systemkey SystemKey.dat /mnt/epe\n"
"  mount -o loop,ro /mnt/epe/trellix-disk /mnt/clear\n"
"\n"
"  trellix-fuse --disk /dev/sda3 --key <hex> --lba-base 2048 --rw /mnt/epe\n"
"  mount -o loop /mnt/epe/trellix-disk /mnt/clear\n",
    me, me, me, me, me);
}

int main(int argc, char **argv)
{
    const char *disk = NULL, *skpath = NULL, *ppkhex = NULL, *ppkfile = NULL;
    const char *keyhex = NULL, *dump = NULL, *mountpoint = NULL;
    const char *algfile = NULL, *epehdr = NULL, *cksec = NULL, *trellix = NULL;
    uint64_t epeoff = 0, troff = 0, pbfslba = 0;
    const char *image = NULL; int partno = 0, listp = 0;
    uint8_t ppkbuf[KEY_LEN] = { 0 }; int have_ppk = 0;
    int secure = 0, probe = 0, have_size = 0, have_lba = 0, findlba = 0;
    int force_hdr = 0, force_lba = 0;
    uint8_t sk[KEY_LEN];
    char **fargv __attribute__((cleanup(free_ptr))) = NULL;
    int fargc = 0, i, c;

    enum { O_DISK = 1000, O_OFF, O_SIZE, O_LBA, O_SEC, O_KEY, O_PPK,
           O_PPKF, O_SK, O_SECURE, O_PROBE, O_DUMP, O_NAME, O_HELP,
           O_ALGID, O_ALGF, O_RAWIV, O_LISTALG, O_RW, O_FORCE,
           O_EPEHDR, O_EPEOFF, O_VERW, O_CKSEC, O_TRELLIX, O_TROFF,
           O_FHDR, O_FLBA, O_IMAGE, O_PART, O_LISTP, O_FINDLBA,
           O_PBFSLBA };
    static const struct option lo[] = {
        { "disk",        required_argument, 0, O_DISK   },
        { "offset",      required_argument, 0, O_OFF    },
        { "size",        required_argument, 0, O_SIZE   },
        { "lba-base",    required_argument, 0, O_LBA    },
        { "sector-size", required_argument, 0, O_SEC    },
        { "key",         required_argument, 0, O_KEY    },
        { "ppk",         required_argument, 0, O_PPK    },
        { "ppk-file",    required_argument, 0, O_PPKF   },
        { "systemkey",   required_argument, 0, O_SK     },
        { "secure",      no_argument,       0, O_SECURE },
        { "probe",       no_argument,       0, O_PROBE  },
        { "dump",        required_argument, 0, O_DUMP   },
        { "name",        required_argument, 0, O_NAME   },
        { "algid",       required_argument, 0, O_ALGID  },
        { "algid-file",  required_argument, 0, O_ALGF   },
        { "raw-iv",      no_argument,       0, O_RAWIV  },
        { "list-algs",   no_argument,       0, O_LISTALG},
        { "rw",          no_argument,       0, O_RW     },
        { "force",       no_argument,       0, O_FORCE  },
        { "force-header",no_argument,       0, O_FHDR   },
        { "force-lba",   no_argument,       0, O_FLBA   },
        { "epe-header",  required_argument, 0, O_EPEHDR },
        { "epe-offset",  required_argument, 0, O_EPEOFF },
        { "verify-writes", no_argument,     0, O_VERW   },
        { "check-sector",required_argument, 0, O_CKSEC  },
        { "trellix",     required_argument, 0, O_TRELLIX},
        { "trellix-offset", required_argument, 0, O_TROFF },
        { "image",       required_argument, 0, O_IMAGE  },
        { "part",        required_argument, 0, O_PART   },
        { "list-parts",  no_argument,       0, O_LISTP  },
        { "find-lba",    no_argument,       0, O_FINDLBA},
        { "pbfs-lba",    required_argument, 0, O_PBFSLBA},
        { "help",        no_argument,       0, O_HELP   },
        { 0, 0, 0, 0 }
    };

    {   /* one argv element can expand into several FUSE args (clustered
         * short options, -oVAL), so size by characters, not by element. */
        size_t cap = 4;
        for (i = 0; i < argc; i++) cap += strlen(argv[i]) + 2;
        if (!(fargv = calloc(cap, sizeof(char *)))) return 1;
    }
    fargv[fargc++] = argv[0];

    opterr = 1;
    while ((c = getopt_long(argc, argv, "+fso:dh", lo, NULL)) != -1) {
        switch (c) {
        case O_DISK: disk = optarg; break;
        case O_OFF:  g.offset = strtoull(optarg, NULL, 0); break;
        case O_SIZE: g.size = strtoull(optarg, NULL, 0); have_size = 1; break;
        case O_LBA:  g.lba_base = strtoull(optarg, NULL, 0); have_lba = 1; break;
        case O_SEC:  g.sector = (unsigned)strtoul(optarg, NULL, 0); break;
        case O_KEY:  keyhex = optarg; break;
        case O_PPK:  ppkhex = optarg; break;
        case O_PPKF: ppkfile = optarg; break;
        case O_SK:   skpath = optarg; break;
        case O_SECURE: secure = 1; break;
        case O_PROBE:  probe = 1; break;
        case O_DUMP:   dump = optarg; break;
        case O_NAME:   g.vname = optarg; break;
        case O_ALGID:  g.algid = (int)strtol(optarg, NULL, 0);
                       g.alg_given = 1; break;
        case O_ALGF:   algfile = optarg; break;
        case O_RAWIV:  g.raw_iv = 1; g.iv_given = 1; break;
        case O_RW:     g.rw = 1; break;
        case O_FORCE:  force_hdr = force_lba = 1; break;
        case O_FHDR:   force_hdr = 1; break;
        case O_FLBA:   force_lba = 1; break;
        case O_EPEHDR: epehdr = optarg; break;
        case O_EPEOFF: epeoff = strtoull(optarg, NULL, 0); break;
        case O_VERW:   g.verify_writes = 1; break;
        case O_CKSEC:  cksec = optarg; break;
        case O_TRELLIX: trellix = optarg; break;
        case O_TROFF:  troff = strtoull(optarg, NULL, 0); break;
        case O_IMAGE:  image = optarg; break;
        case O_PART:   partno = (int)strtol(optarg, NULL, 0); break;
        case O_LISTP:  listp = 1; break;
        case O_FINDLBA: findlba = 1; break;
        case O_PBFSLBA: pbfslba = strtoull(optarg, NULL, 0); break;
        case O_LISTALG: {
            int q;
            printf("id   name             per-sector construction\n");
            for (q = 0; q < NALGS; q++)
                printf("%-4d %-16s %s\n", ALGS[q].id, ALGS[q].name,
                       (ALGS[q].id == ALG_RC5_12 || ALGS[q].id == ALG_RC5_18)
                       ? "64-bit CBC, IV = (n, n^D5E74364), no key expansion"
                       : "128-bit CBC, IV = E(K, n|n|n|n)");
            return 0; }
        case O_HELP: case 'h': usage(argv[0]); return 0;
        /* pass FUSE's own flags straight through */
        case 'f': fargv[fargc++] = "-f"; break;
        case 's': fargv[fargc++] = "-s"; break;
        case 'd': fargv[fargc++] = "-d"; break;
        case 'o': fargv[fargc++] = "-o"; fargv[fargc++] = optarg; break;
        default: usage(argv[0]); return 2;
        }
    }
    for (i = optind; i < argc; i++) {
        if (!mountpoint && argv[i][0] != '-')
            mountpoint = argv[i];
        fargv[fargc++] = argv[i];
    }

    /* ---- standalone: verify any EPE metadata sector ---- */
    if (cksec) {
        uint8_t sec[512];
        FILE *f = fopen(cksec, "rb");
        uint32_t sum;
        const char *why;
        if (!f) { perror(cksec); return 1; }
        if (fseeko(f, (off_t)epeoff, SEEK_SET) != 0
            || fread(sec, 1, 512, f) != 512) {
            fprintf(stderr, "%s: cannot read 512 bytes at offset %llu\n",
                    cksec, (unsigned long long)epeoff);
            fclose(f); return 1;
        }
        fclose(f);
        sum = epe_sector_checksum(sec);
        printf("sector    : %s +%llu\n", cksec, (unsigned long long)epeoff);
        printf("somme     : 0x%08x  %s\n", sum,
               sum == 0 ? "VALID (the sector sums to zero)" : "INVALID");
        printf("crc32     : 0x%08x\n", epe_crc32(0, sec, 512));
        if (!memcmp(sec, EPE_HDR_MAGIC, 16)) {
            printf("type      : EPE partition header\n");
            printf("header    : %s\n",
                   epe_header_valid(sec, &why) ? "VALID (firmware check)" : why);
            printf("PBFS      : LBA %lld, %u sectors\n",
                   (long long)(int64_t)(ld32(sec + 0x2C)
                        | ((uint64_t)ld32(sec + 0x30) << 32)),
                   ld32(sec + 0x34));
        }
        return sum == 0 ? 0 : 1;
    }

    if (!disk && !image) { fprintf(stderr, "error: --disk or --image is required\n\n");
                 usage(argv[0]); return 2; }
    /* ---- whole-disk image: find the partitions ourselves ---- */
    if (image) {
        struct part parts[MAX_PARTS];
        const char *kind = NULL;
        int np, i, epe = -1, target = -1, ifd;

        if ((ifd = open(image, O_RDONLY | O_LARGEFILE)) < 0) { perror(image); return 1; }
        np = scan_parts(ifd, parts, MAX_PARTS, &kind);
        if (np <= 0) {
            fprintf(stderr, "%s: no GPT or MBR partition table recognised.\n"
                            "  If this is a PARTITION image rather than a disk "
                            "image, use --disk.\n", image);
            close(ifd); return 1;
        }
        if (listp) { list_parts(stdout, parts, np, kind); close(ifd); return 0; }

        for (i = 0; i < np; i++)
            if (parts[i].mbr_type < 0 && !memcmp(parts[i].type, EPE_TYPE_GUID, 16))
                epe = i;

        if (partno) {
            if (partno < 1 || partno > np) {
                fprintf(stderr, "error: --part %d is outside the table (%d "
                                "partitions)\n", partno, np);
                close(ifd); return 1;
            }
            target = partno - 1;
        } else {
            /* Largest partition that is neither the Trellix one nor an ESP. */
            uint64_t best = 0;
            for (i = 0; i < np; i++) {
                if (i == epe) continue;
                if (parts[i].mbr_type < 0
                    && !memcmp(parts[i].type, ESP_TYPE_GUID, 16)) continue;
                if (parts[i].count > best) { best = parts[i].count; target = i; }
            }
            if (target < 0) {
                fprintf(stderr, "error: no candidate partition; "
                                "pass --part (see --list-parts)\n");
                close(ifd); return 1;
            }
        }
        close(ifd);

        list_parts(stderr, parts, np, kind);

        disk     = image;
        g.offset = parts[target].start * 512;
        g.size   = parts[target].count * 512;   have_size = 1;
        g.lba_base = parts[target].start;       have_lba  = 1;
        fprintf(stderr, "target    : partition %d, LBA %llu, %llu sectors\n",
                target + 1, (unsigned long long)parts[target].start,
                (unsigned long long)parts[target].count);

        if (keyhex || skpath) {
            fprintf(stderr, "trellix   : ignored, an explicit key was supplied\n");
        } else if (!trellix && epe >= 0) {
            trellix = image;
            troff   = parts[epe].start * 512;
            fprintf(stderr, "trellix   : partition %d of the same image "
                            "(LBA %llu)\n",
                    epe + 1, (unsigned long long)parts[epe].start);
        } else if (!trellix) {
            fprintf(stderr, "trellix   : no McAfeeEpeReserved partition in "
                            "the image.\n"
                            "            Pass --trellix, or --key if you "
                            "already have the disk key.\n");
        }
    }
    if (listp && !image) {
        fprintf(stderr, "error: --list-parts requires --image\n");
        return 2;
    }

    if (g.sector < 16 || g.sector > MAX_SECTOR || (g.sector % 16)) {
        fprintf(stderr, "error: invalid sector size (%u)\n", g.sector);
        return 2;
    }
    if (g.offset % g.sector) {
        fprintf(stderr, "error: --offset (%llu) must be a multiple of the "
                        "sector size (%u)\n",
                (unsigned long long)g.offset, g.sector);
        return 2;
    }
    if (trellix && !image) {
        if (keyhex || skpath || secure) {
            fprintf(stderr, "error: --trellix derives everything itself; "
                            "--key, --systemkey and --secure are incompatible\n");
            return 2;
        }
    }
    if (trellix) {
        if (g.sector != 512) {
            fprintf(stderr, "error: --trellix assumes 512-byte sectors "
                            "(both the sysfs LBA and the PBFS LBA are)\n");
            return 2;
        }
    }

    if (algfile) {
        uint8_t four[4];
        if (read_file(algfile, four, 4)) return 2;
        g.algid = (int)((uint32_t)four[0] | ((uint32_t)four[1] << 8)
                      | ((uint32_t)four[2] << 16) | ((uint32_t)four[3] << 24));
        g.alg_given = 1;
        fprintf(stderr, "AlgId.dat : id %d (%s)\n", g.algid, alg_name(g.algid));
    }
    if (g.alg_given && g.algid != ALG_AES256 && g.algid != ALG_SBAES256
        && g.algid != ALG_RC5_12 && g.algid != ALG_RC5_18) {
        fprintf(stderr, "error: unknown algorithm %d (--list-algs)\n", g.algid);
        return 2;
    }

    /* ---- the PPK, whichever way it was given ---- */
    if (ppkfile) {
        struct stat pst;
        if (stat(ppkfile, &pst) == 0 && S_ISREG(pst.st_mode)
            && pst.st_size != KEY_LEN) {
            fprintf(stderr, "error: %s is %lld bytes, expected %d.\n"
                            "  (a file of 64 hex characters goes with --ppk, "
                            "not --ppk-file)\n",
                    ppkfile, (long long)pst.st_size, KEY_LEN);
            return 2;
        }
        if (read_file(ppkfile, ppkbuf, KEY_LEN)) return 2;
        have_ppk = 1;
    } else if (ppkhex) {
        if (unhex(ppkhex, ppkbuf, KEY_LEN)) {
            fprintf(stderr, "error: --ppk must be 64 hex characters\n");
            return 2;
        }
        have_ppk = 1;
    }

    /* ---- fully automatic: derive everything from the Trellix partition ---- */
    if (trellix) {
        struct autoresult a = auto_from_trellix(trellix, troff, ppkbuf,
                                               have_ppk, pbfslba);
        if (!a.ok) {
            fprintf(stderr, "\nautomatic derivation failed.\n");
            return 1;
        }
        memcpy(g.key, a.key, KEY_LEN);
        if (!g.alg_given) { g.algid = a.algid; g.alg_given = 1; }
        keyhex = NULL; skpath = NULL;          /* the auto path wins */
        /* The firmware encrypts with the absolute LBA on the disk. When --disk
         * is a partition block device, its start LBA is right there in sysfs. */
        if (!have_lba) {
            uint64_t st;
            if (part_start_lba(disk, &st) == 0) {
                /* sysfs reports the start in 512-byte units, always. */
                g.lba_base = st + g.offset / g.sector;
                have_lba = 1;
                fprintf(stderr, "LBA base  : %llu (start of %s from sysfs%s)\n",
                        (unsigned long long)g.lba_base, disk,
                        g.offset ? " + --offset" : "");
            } else {
                fprintf(stderr,
                    "LBA base  : %s is not a block partition, its start LBA "
                    "could not be read.\n"
                    "            The firmware encrypts with the disk's ABSOLUTE "
                    "LBA: pass --lba-base,\n"
                    "            or run --probe to find it.\n", disk);
            }
        }
        goto key_ready;
    }

    /* ---- assemble the disk key ---- */
    if (keyhex) {
        if (unhex(keyhex, g.key, KEY_LEN)) {
            fprintf(stderr, "error: --key must be 64 hex characters\n");
            return 2;
        }
    } else if (skpath) {
        if (read_file(skpath, sk, KEY_LEN)) return 2;
        if (secure) {
            memcpy(g.key, sk, KEY_LEN);
        } else {
            if (!have_ppk) {
                fprintf(stderr, "error: --systemkey without --secure requires "
                                "--ppk or --ppk-file\n");
                return 2;
            }
            for (i = 0; i < KEY_LEN; i++)
                g.key[i] = (uint8_t)(sk[i] ^ ppkbuf[i]);
        }
    } else {
        fprintf(stderr, "error: pass --trellix, --key, or --systemkey\n");
        return 2;
    }
key_ready:

    rc5_setkey(g.rc5ctx, g.key, KEY_LEN);

    /* ---- open the disk ---- */
    if ((g.fd = open(disk, (g.rw ? O_RDWR : O_RDONLY) | O_LARGEFILE)) < 0) {
        perror(disk); return 1;
    }
    {
        uint64_t total = file_size(g.fd);
        if (!have_size) {
            if (total <= g.offset) {
                fprintf(stderr, "error: --offset is past the end of %s\n", disk);
                return 1;
            }
            g.size = total - g.offset;
        }
        g.size -= g.size % g.sector;         /* whole sectors only */
        if (!g.size) { fprintf(stderr, "error: empty region\n"); return 1; }
        /* Never let the region run past the backing store. Otherwise a short
         * pread in write_plain would decrypt a zero-filled buffer into
         * pseudo-random plaintext and commit a whole fabricated sector. */
        if (total && g.offset + g.size > total) {
            fprintf(stderr,
                "error: the region (offset %llu + %llu bytes) is past the end "
                "of %s (%llu bytes)\n",
                (unsigned long long)g.offset, (unsigned long long)g.size,
                disk, (unsigned long long)total);
            return 1;
        }
    }
    if (!have_lba)
        g.lba_base = g.offset / g.sector;

    fprintf(stderr,
        "disk      : %s\n"
        "region    : offset %llu, %llu bytes (%llu sectors of %u)\n"
        "LBA base  : %llu\n"
        "algorithm : %s (id %d)%s\n"
        "mode      : %s\n",
        disk,
        (unsigned long long)g.offset, (unsigned long long)g.size,
        (unsigned long long)(g.size / g.sector), g.sector,
        (unsigned long long)g.lba_base,
        alg_name(g.algid), g.algid,
        (g.algid == ALG_AES256 || g.algid == ALG_SBAES256)
            ? (g.raw_iv ? ", raw IV" : ", IV = E(K, n|n|n|n)")
            : ", IV = (n, n^D5E74364)",
        g.rw ? "READ-WRITE" : "read-only");

    if (epehdr) {
        uint8_t sec[512];
        const char *why = NULL;
        FILE *f = fopen(epehdr, "rb");
        if (!f) { perror(epehdr); return 1; }
        if (fseeko(f, (off_t)epeoff, SEEK_SET) != 0
            || fread(sec, 1, 512, f) != 512) {
            fprintf(stderr, "%s: header unreadable\n", epehdr); fclose(f); return 1;
        }
        fclose(f);
        if (epe_header_valid(sec, &why)) {
            fprintf(stderr, "header    : EPE valid (magic + zero sum + fields), "
                            "PBFS at LBA %lld over %u sectors\n",
                    (long long)(int64_t)(ld32(sec + 0x2C)
                         | ((uint64_t)ld32(sec + 0x30) << 32)),
                    ld32(sec + 0x34));
        } else {
            fprintf(stderr,
                "\nINVALID EPE HEADER: %s\n"
                "  This is not a McAfeeEpeReserved partition at this offset, or\n"
                "  it is corrupt. Check transcribed from get_valid_epe_header.\n", why);
            if (!force_hdr) return 1;
            fprintf(stderr, "  continuing anyway (--force-header)\n");
        }
    }

    if (probe) return do_probe();
    if (findlba) return do_find_lba();
    if (dump)  return do_dump(dump);

    /* ------------------------------------------------------------------
     * Preflight. Runs before EVERY mount, read-only included.
     *
     * A wrong sector base is invisible in CBC: only the first 16 bytes of each
     * sector come out wrong, so a filesystem still "mounts" while every sector
     * is quietly mangled. Read-only that means silently wrong data; read-write
     * it means irreversible destruction. So we never mount on trust: we
     * decrypt the head of the region and require a signature that lives inside
     * the first block. If the configured base does not confirm, we sweep the
     * plausible ones and adopt the one that does.
     * ------------------------------------------------------------------ */
    {
        size_t span = 128 * 1024;
        uint8_t *buf;
        struct ident id = { NULL, 0 };
        uint64_t cands[4], adopted = g.lba_base;
        unsigned ncand = 0, k;
        int found = 0;
        const char *recovered = NULL;

        if (span > g.size) span = (size_t)g.size;
        cands[ncand++] = g.lba_base;
        if (g.lba_base != 0)                   cands[ncand++] = 0;
        if (g.offset / g.sector != g.lba_base) cands[ncand++] = g.offset / g.sector;

        if ((buf = malloc(span)) == NULL) { perror("malloc"); return 1; }

        for (k = 0; k < ncand && !found; k++) {
            ssize_t got;
            g.lba_base = cands[k];
            got = read_plain(buf, span, 0);
            if (got > 0) {
                struct ident t = identify(buf, (size_t)got);
                if (t.confirms_base) { id = t; adopted = cands[k]; found = 1; }
                else if (t.name && !id.name) id = t;      /* key ok at least */
            }
        }
        /* The sweep above only tries bases we could guess. When none of them
         * confirms, the base can still be *computed* rather than searched: in
         * CBC only the first block of a sector depends on the IV, and the IV
         * is a known function of the sector number. Sixteen known plaintext
         * bytes - which NTFS, exFAT and FAT32 all hand us - are enough to
         * invert it. This is what makes a bare partition image mountable: such
         * an image carries no absolute LBA anywhere. */
        if (!found) {
            uint64_t rec = 0;
            const char *how = NULL;
            if (recover_lba_base_sweep(&rec, &how) == 0) {
                ssize_t got;
                g.lba_base = rec;
                got = read_plain(buf, span, 0);
                if (got > 0) {
                    struct ident t = identify(buf, (size_t)got);
                    if (t.confirms_base) {
                        id = t; adopted = rec; found = 1; recovered = how;
                    } else if (t.name && !id.name) id = t;
                }
            }
        }

        g.lba_base = adopted;
        free(buf);

        if (found) {
            fprintf(stderr, "check     : %s recognised%s, LBA base %llu confirmed\n",
                    id.name,
                    recovered ? " (base computed)"
                              : (cands[0] != adopted)
                                    ? " (base corrected automatically)" : "",
                    (unsigned long long)adopted);
            if (recovered)
                fprintf(stderr,
                    "            base derived from known plaintext: %s\n"
                    "            algorithm chosen: %s (id %d)%s\n",
                    recovered, alg_name(g.algid), g.algid,
                    (g.algid == ALG_AES256 || g.algid == ALG_SBAES256)
                        ? (g.raw_iv ? ", raw IV" : ", encrypted IV") : "");
        } else if (force_lba) {
            fprintf(stderr, "check     : LBA base NOT confirmed - "
                            "continuing anyway (--force-lba)\n");
        } else {
            fprintf(stderr,
"\nREFUSING TO MOUNT: the pre-mount check did not confirm the LBA base.\n"
"\n"
"  %s\n"
"\n"
"  In CBC a wrong LBA base corrupts only the first 16 bytes of each sector.\n"
"  The filesystem would appear to mount while every sector is altered -\n"
"  silently on read, permanently on write, the encryption carrying no\n"
"  integrity check of any kind.\n"
"\n"
"  Bases tried:",
                id.name ? "A signature was recognised beyond the 16th byte: the key is\n"
                          "  correct, but the sector numbering is not."
                        : "No signature recognised: check the key, --offset and --algid.");
            for (k = 0; k < ncand; k++)
                fprintf(stderr, " %llu", (unsigned long long)cands[k]);
            fprintf(stderr,
"\n  Analytic reconstruction of the base (known NTFS / exFAT / FAT32\n"
"  plaintext) also failed - see --find-lba for the detail.\n"
"  Run --probe to sweep the algorithms as well, or pass --lba-base.\n"
"  --force-lba overrides this, at your own risk.\n");
            return 1;
        }
    }

    if (!mountpoint) {
        fprintf(stderr, "\nerror: give a mountpoint "
                        "(or use --probe / --dump)\n");
        return 2;
    }
    fprintf(stderr, "mount     : %s/%s (%s)\n\n", mountpoint, g.vname,
            g.rw ? "read-write" : "read-only");
    return fuse_main(fargc, fargv, &cf_ops, NULL);
}
