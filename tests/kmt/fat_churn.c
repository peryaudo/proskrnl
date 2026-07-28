/* tests/kmt/fat_churn.c — FS churn stress with an in-kernel shadow model,
 * verified cold across a reboot (docs/08 "The FAT on-disk format has its
 * own oracles"; the section_stress fixed-seed precedent).
 *
 * A fixed-seed PRNG drives random create / whole-rewrite / partial-write /
 * extend / truncate / delete / mkdir-rmdir / enumerate ops under C:\churn
 * against the real Nt* surface, with an in-memory shadow model verified as
 * it goes. The load-bearing invariant: THE SHADOW ADVANCES FROM THE PRNG
 * AND THE SHADOW ALONE — never from FS feedback — so re-running the
 * generator with I/O suppressed ("dry") reconstructs the exact final state
 * from nothing but the seed.
 *
 * Two-boot protocol (the m8_persist pattern; run.sh fatstress):
 *   boot 1  C:\churn absent -> create it, run the churn WET, full-verify,
 *           dump `[CHURN] F <path> <size> <crc32>` lines, verdict
 *           `[KTEST] churn-seed PASS`.
 *   boot 2  C:\churn present -> replay DRY (no I/O), then verify the whole
 *           tree against the reconstructed shadow through a COLD cache —
 *           the only way in-kernel reads exercise the on-disk bytes rather
 *           than boot 1's warm page cache. Verdict `[KTEST] churn-verify`.
 * The host then extracts C:\churn with mcopy and re-verifies the dump
 * independently (tests/run/churn_verify.py), and diffs the two boots'
 * dumps (a free determinism check on the replay).
 *
 * File content is a pure function of (extentSeed, absoluteOffset), so
 * partial writes/truncates/extends only edit a small extent list; bytes are
 * recomputable at verify time without storing them. CRC32 is the reflected
 * IEEE polynomial 0xEDB88320, init/xorout 0xFFFFFFFF (ITU-T V.42 §8.1.1.6.2
 * / RFC 1952 §8) — the same function as python's zlib.crc32 on the host.
 *
 * Gating: runs only when C:\churn.cfg exists (the image decides — the
 * ntapi-sweep precedent, user/smss/session.c). The config line carries
 *   seed=0x... ops=N maxfiles=N maxsize=N budget=N expect_diskfull=0|1
 * so run.sh legs vary geometry/pressure without a kernel rebuild. On an
 * expect_diskfull leg STATUS_DISK_FULL timing depends on real allocation
 * state, so the shadow cannot be replayed dry — those legs boot once and
 * boot 2 (if any) skips.
 */
#include "tests/kmt/kmt.h"
#include "kernel/io/io.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"

#include "abi/ntstatus.h"
#include "abi/ntioapi.h"

#define CHURN_MAX_FILES   64
#define CHURN_MAX_DIRS    4
#define CHURN_MAX_EXTENTS 8
#define CHURN_NAME_CHARS  24
#define CHURN_PATH_CHARS  64

/* --- config ----------------------------------------------------------------- */

static struct
{
    ULONG seed;
    ULONG ops;
    ULONG maxfiles; /* <= CHURN_MAX_FILES */
    ULONG maxsize;  /* whole-file write cap; extends may reach 2x */
    uint64_t budget;
    BOOLEAN expectDiskFull;
} churn_cfg;

/* --- shadow model ------------------------------------------------------------ */

typedef struct churn_extent
{
    uint64_t start, end; /* [start, end); bytes outside every extent read 0 */
    ULONG seed;
} churn_extent;

typedef struct churn_file
{
    BOOLEAN inUse;
    int dir; /* -1 = C:\churn itself, else subdir index */
    WCHAR name[CHURN_NAME_CHARS];
    USHORT nameChars;
    uint64_t size;
    churn_extent extents[CHURN_MAX_EXTENTS];
    int extentCount;
} churn_file;

static churn_file churn_files[CHURN_MAX_FILES]; /* bss, not the kmt stack */
static BOOLEAN churn_dirs[CHURN_MAX_DIRS];
static uint64_t churn_total_bytes;
static ULONG churn_name_counter;
static int churn_diskfull;
static char *churn_buffer; /* 2*maxsize pool scratch */
static char *churn_model;  /* second scratch for expected bytes */

/* xorshift32, fixed seed (the section_stress precedent). */
static ULONG churn_rng_state;
static ULONG churn_rng(void)
{
    ULONG x = churn_rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return churn_rng_state = x;
}

/* Content byte at absolute offset o under extent seed s (splitmix64-style
 * mixer; only determinism matters). */
static unsigned char churn_byte(ULONG s, uint64_t o)
{
    uint64_t x = ((uint64_t)s << 32 | (o >> 3)) * 0x9E3779B97F4A7C15ull;
    x ^= x >> 29;
    x *= 0xBF58476D1CE4E5B9ull;
    x ^= x >> 32;
    return (unsigned char)(x >> ((o & 7) * 8));
}

static void churn_model_fill(const churn_file *f, char *out, uint64_t offset, ULONG length)
{
    memset(out, 0, length);
    for (int i = 0; i < f->extentCount; i++)
    {
        const churn_extent *e = &f->extents[i];
        uint64_t from = e->start > offset ? e->start : offset;
        uint64_t to = e->end < offset + length ? e->end : offset + length;
        for (uint64_t o = from; o < to; o++)
        {
            out[o - offset] = (char)churn_byte(e->seed, o);
        }
    }
}

/* Insert [start,end) with `seed`, clipping/splitting overlaps; FALSE (no
 * change) when the result would exceed CHURN_MAX_EXTENTS — the caller then
 * degrades the op to a whole-file rewrite, keeping per-file state bounded. */
static BOOLEAN churn_extent_insert(churn_file *f, uint64_t start, uint64_t end, ULONG seed)
{
    churn_extent result[CHURN_MAX_EXTENTS + 2];
    int n = 0;
    for (int i = 0; i < f->extentCount; i++)
    {
        churn_extent e = f->extents[i];
        if (e.end <= start || e.start >= end)
        {
            result[n++] = e;
            continue;
        }
        if (e.start < start)
        {
            churn_extent head = {e.start, start, e.seed};
            result[n++] = head;
        }
        if (e.end > end)
        {
            churn_extent tail = {end, e.end, e.seed};
            result[n++] = tail;
        }
        if (n > CHURN_MAX_EXTENTS + 1)
        {
            return FALSE;
        }
    }
    churn_extent fresh = {start, end, seed};
    result[n++] = fresh;
    if (n > CHURN_MAX_EXTENTS)
    {
        return FALSE;
    }
    /* Keep sorted by start (insertion sort; n is tiny). */
    for (int i = 1; i < n; i++)
    {
        churn_extent key = result[i];
        int j = i - 1;
        while (j >= 0 && result[j].start > key.start)
        {
            result[j + 1] = result[j];
            j--;
        }
        result[j + 1] = key;
    }
    memcpy(f->extents, result, (unsigned)n * sizeof(churn_extent));
    f->extentCount = n;
    return TRUE;
}

static void churn_extent_truncate(churn_file *f, uint64_t newSize)
{
    int n = 0;
    for (int i = 0; i < f->extentCount; i++)
    {
        churn_extent e = f->extents[i];
        if (e.start >= newSize)
        {
            continue;
        }
        if (e.end > newSize)
        {
            e.end = newSize;
        }
        f->extents[n++] = e;
    }
    f->extentCount = n;
}

static void churn_set_whole(churn_file *f, uint64_t size, ULONG seed)
{
    f->extentCount = 0;
    f->size = size;
    if (size != 0)
    {
        churn_extent whole = {0, size, seed};
        f->extents[0] = whole;
        f->extentCount = 1;
    }
}

/* --- CRC32 (reflected 0xEDB88320, init/xorout 0xFFFFFFFF — ITU-T V.42 /
 * RFC 1952; equals python zlib.crc32) ---------------------------------------- */

static uint32_t churn_crc_update(uint32_t crc, const void *data, ULONG length)
{
    const unsigned char *p = data;
    for (ULONG i = 0; i < length; i++)
    {
        crc ^= p[i];
        for (int b = 0; b < 8; b++)
        {
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1)));
        }
    }
    return crc;
}

/* --- paths ------------------------------------------------------------------- */

static const WCHAR *churn_nt_path(int dir, const churn_file *f)
{
    static WCHAR path[64 + CHURN_NAME_CHARS];
    int n = 0;
    static const WCHAR prefix[] = WSTR("\\??\\C:\\churn");
    while (prefix[n] != 0)
    {
        path[n] = prefix[n];
        n++;
    }
    if (dir >= 0)
    {
        path[n++] = '\\';
        path[n++] = 'd';
        path[n++] = (WCHAR)('0' + dir);
    }
    if (f != 0)
    {
        path[n++] = '\\';
        for (USHORT i = 0; i < f->nameChars; i++)
        {
            path[n++] = f->name[i];
        }
    }
    path[n] = 0;
    return path;
}

static const char *churn_rel_path(const churn_file *f)
{
    static char rel[CHURN_PATH_CHARS];
    int n = 0;
    const char *base = "churn";
    while (*base != 0)
    {
        rel[n++] = *base++;
    }
    if (f->dir >= 0)
    {
        rel[n++] = '/';
        rel[n++] = 'd';
        rel[n++] = (char)('0' + f->dir);
    }
    rel[n++] = '/';
    for (USHORT i = 0; i < f->nameChars; i++)
    {
        rel[n++] = (char)f->name[i];
    }
    rel[n] = 0;
    return rel;
}

static void init_attr(OBJECT_ATTRIBUTES *attr, UNICODE_STRING *name, const WCHAR *path)
{
    RtlInitUnicodeString(name, path);
    memset(attr, 0, sizeof(*attr));
    attr->Length = sizeof(*attr);
    attr->ObjectName = name;
    attr->Attributes = OBJ_CASE_INSENSITIVE;
}

/* --- wet executors (every status is asserted; the shadow NEVER consults
 * them — a wet failure is a loud test failure, not a model branch) ---------- */

/* Returns 0 on success, 1 when STATUS_DISK_FULL forced a corrective
 * truncate-to-zero (the file exists, empty), 2 when the create itself hit
 * DISK_FULL (no file). Nonzero only ever happens on expect_diskfull legs
 * (asserted by the caller's diskfull accounting), which never dry-replay,
 * so the shadow may follow the outcome. */
static int churn_wet_write(const churn_file *f, uint64_t offset, ULONG length, ULONG seed,
                           ULONG disposition, ULONG iter)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    init_attr(&attr, &name, churn_nt_path(f->dir, f));
    NTSTATUS status = NtCreateFile(&handle, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attr, &iosb, 0,
                                   FILE_ATTRIBUTE_NORMAL, 0, disposition,
                                   FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, 0, 0);
    if (status == STATUS_DISK_FULL && churn_cfg.expectDiskFull)
    {
        churn_diskfull++;
        return 2;
    }
    ok(status == STATUS_SUCCESS, "iter %lu: open/create %s -> %08lx", iter, churn_rel_path(f),
       (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        return 2;
    }
    uint64_t done = 0;
    while (done < length)
    {
        ULONG chunk = length - done > 0x10000 ? 0x10000 : (ULONG)(length - done);
        for (ULONG i = 0; i < chunk; i++)
        {
            churn_buffer[i] = (char)churn_byte(seed, offset + done + i);
        }
        LARGE_INTEGER at;
        at.QuadPart = (LONGLONG)(offset + done);
        status = NtWriteFile(handle, 0, 0, 0, &iosb, churn_buffer, chunk, &at, 0);
        if (status == STATUS_DISK_FULL)
        {
            break; /* handled by the caller via churn_diskfull */
        }
        ok(status == STATUS_SUCCESS && iosb.Information == chunk,
           "iter %lu: write %s at %lu -> %08lx", iter, churn_rel_path(f), (unsigned long)done,
           (unsigned long)status);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        done += chunk;
    }
    if (status == STATUS_DISK_FULL)
    {
        /* Corrective truncate-to-zero: the failed chunk's grow unwound
         * itself (fs/fat32/file.c FatSetFileSize), but earlier chunks of
         * this write may already have extended the file; the shrink leaves
         * a consistent, empty file the shadow mirrors. */
        FILE_END_OF_FILE_INFORMATION eof;
        eof.EndOfFile.QuadPart = 0;
        NtSetInformationFile(handle, &iosb, &eof, sizeof(eof), FileEndOfFileInformation);
        churn_diskfull++;
        NtClose(handle);
        return 1;
    }
    NtClose(handle);
    return 0;
}

/* Returns TRUE when the resize stuck; FALSE when DISK_FULL rolled it back
 * to oldSize (expect_diskfull legs only). */
static BOOLEAN churn_wet_seteof(const churn_file *f, uint64_t newSize, uint64_t oldSize, ULONG iter)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    init_attr(&attr, &name, churn_nt_path(f->dir, f));
    NTSTATUS status = NtOpenFile(&handle, FILE_GENERIC_WRITE, &attr, &iosb, 0,
                                 FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    ok(status == STATUS_SUCCESS, "iter %lu: open %s -> %08lx", iter, churn_rel_path(f),
       (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        return TRUE;
    }
    FILE_END_OF_FILE_INFORMATION eof;
    eof.EndOfFile.QuadPart = (LONGLONG)newSize;
    status = NtSetInformationFile(handle, &iosb, &eof, sizeof(eof), FileEndOfFileInformation);
    BOOLEAN stuck = TRUE;
    if (status == STATUS_DISK_FULL)
    {
        eof.EndOfFile.QuadPart = (LONGLONG)oldSize;
        NtSetInformationFile(handle, &iosb, &eof, sizeof(eof), FileEndOfFileInformation);
        churn_diskfull++;
        stuck = FALSE;
    }
    else
    {
        ok(status == STATUS_SUCCESS, "iter %lu: set-eof %s to %lu -> %08lx", iter,
           churn_rel_path(f), (unsigned long)newSize, (unsigned long)status);
    }
    NtClose(handle);
    return stuck;
}

static void churn_wet_delete(const churn_file *f, ULONG iter)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    init_attr(&attr, &name, churn_nt_path(f->dir, f));
    NTSTATUS status = NtOpenFile(&handle, DELETE | SYNCHRONIZE, &attr, &iosb,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    ok(status == STATUS_SUCCESS, "iter %lu: open-for-delete %s -> %08lx", iter, churn_rel_path(f),
       (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        return;
    }
    FILE_DISPOSITION_INFORMATION disposition;
    disposition.DoDeleteFile = TRUE;
    status = NtSetInformationFile(handle, &iosb, &disposition, sizeof(disposition),
                                  FileDispositionInformation);
    ok(status == STATUS_SUCCESS, "iter %lu: dispose %s -> %08lx", iter, churn_rel_path(f),
       (unsigned long)status);
    NtClose(handle);
    status = NtOpenFile(&handle, FILE_GENERIC_READ, &attr, &iosb, FILE_SHARE_READ,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "iter %lu: deleted %s still opens -> %08lx", iter,
       churn_rel_path(f), (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        NtClose(handle);
    }
}

static void churn_wet_mkdir(int dir, ULONG iter)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    init_attr(&attr, &name, churn_nt_path(dir, 0));
    NTSTATUS status =
        NtCreateFile(&handle, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attr, &iosb, 0,
                     FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE,
                     FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    ok(status == STATUS_SUCCESS, "iter %lu: mkdir d%d -> %08lx", iter, dir, (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        NtClose(handle);
    }
}

static void churn_wet_rmdir(int dir, BOOLEAN expectEmpty, ULONG iter)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    init_attr(&attr, &name, churn_nt_path(dir, 0));
    NTSTATUS status = NtOpenFile(&handle, DELETE | SYNCHRONIZE, &attr, &iosb,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE);
    ok(status == STATUS_SUCCESS, "iter %lu: open d%d -> %08lx", iter, dir, (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        return;
    }
    FILE_DISPOSITION_INFORMATION disposition;
    disposition.DoDeleteFile = TRUE;
    status = NtSetInformationFile(handle, &iosb, &disposition, sizeof(disposition),
                                  FileDispositionInformation);
    if (expectEmpty)
    {
        ok(status == STATUS_SUCCESS, "iter %lu: rmdir d%d -> %08lx", iter, dir,
           (unsigned long)status);
    }
    else
    {
        /* A non-empty directory must refuse the delete intent (NT rule). */
        ok(status == STATUS_DIRECTORY_NOT_EMPTY, "iter %lu: rmdir non-empty d%d -> %08lx", iter,
           dir, (unsigned long)status);
    }
    NtClose(handle);
}

/* A rename probe: FileRenameInformation is not implemented (kernel/io/
 * query.c default arm). This pins today's boundary — the day rename lands,
 * this fails loudly and the shadow model must learn the op. */
static void churn_wet_rename_probe(const churn_file *f, ULONG iter)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    init_attr(&attr, &name, churn_nt_path(f->dir, f));
    NTSTATUS status = NtOpenFile(&handle, FILE_GENERIC_WRITE | DELETE, &attr, &iosb, 0,
                                 FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(status))
    {
        ok(0, "iter %lu: open %s -> %08lx", iter, churn_rel_path(f), (unsigned long)status);
        return;
    }
    unsigned char info[64];
    memset(info, 0, sizeof(info));
    status = NtSetInformationFile(handle, &iosb, info, sizeof(info), FileRenameInformation);
    ok(status == STATUS_NOT_IMPLEMENTED, "iter %lu: rename probe -> %08lx", iter,
       (unsigned long)status);
    NtClose(handle);
}

/* --- verification (wet or cold) ---------------------------------------------- */

static void churn_verify_file(const churn_file *f, ULONG iter)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    init_attr(&attr, &name, churn_nt_path(f->dir, f));
    NTSTATUS status = NtOpenFile(&handle, FILE_GENERIC_READ, &attr, &iosb, FILE_SHARE_READ,
                                 FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    ok(status == STATUS_SUCCESS, "iter %lu: verify-open %s -> %08lx", iter, churn_rel_path(f),
       (unsigned long)status);
    if (!NT_SUCCESS(status))
    {
        return;
    }
    FILE_STANDARD_INFORMATION standard;
    status =
        NtQueryInformationFile(handle, &iosb, &standard, sizeof(standard), FileStandardInformation);
    ok(NT_SUCCESS(status) && (uint64_t)standard.EndOfFile.QuadPart == f->size,
       "iter %lu: %s EOF %lu want %lu", iter, churn_rel_path(f),
       (unsigned long)standard.EndOfFile.QuadPart, (unsigned long)f->size);

    uint64_t done = 0;
    while (done < f->size)
    {
        ULONG chunk = f->size - done > 0x10000 ? 0x10000 : (ULONG)(f->size - done);
        LARGE_INTEGER at;
        at.QuadPart = (LONGLONG)done;
        status = NtReadFile(handle, 0, 0, 0, &iosb, churn_buffer, chunk, &at, 0);
        if (!NT_SUCCESS(status) || iosb.Information != chunk)
        {
            ok(0, "iter %lu: verify-read %s at %lu -> %08lx", iter, churn_rel_path(f),
               (unsigned long)done, (unsigned long)status);
            break;
        }
        churn_model_fill(f, churn_model, done, chunk);
        if (memcmp(churn_buffer, churn_model, chunk) != 0)
        {
            ULONG bad = 0;
            while (bad < chunk && churn_buffer[bad] == churn_model[bad])
            {
                bad++;
            }
            ok(0, "iter %lu: %s content differs at byte %lu (saw %02x want %02x)", iter,
               churn_rel_path(f), (unsigned long)(done + bad), (unsigned char)churn_buffer[bad],
               (unsigned char)churn_model[bad]);
            break;
        }
        done += chunk;
    }
    NtClose(handle);
}

typedef struct churn_enum_ctx
{
    int dir; /* -1 = C:\churn */
    ULONG iter;
    BOOLEAN seen[CHURN_MAX_FILES];
    BOOLEAN seenDir[CHURN_MAX_DIRS];
    int unexpected;
} churn_enum_ctx;

static BOOLEAN churn_enum_callback(const IO_DIR_ENTRY *entry, PVOID context)
{
    churn_enum_ctx *ctx = context;
    USHORT nameChars = (USHORT)(entry->nameLength / sizeof(WCHAR));
    if ((nameChars == 1 && entry->name[0] == '.') ||
        (nameChars == 2 && entry->name[0] == '.' && entry->name[1] == '.'))
    {
        return TRUE;
    }
    if (ctx->dir == -1 && entry->info.isDirectory && nameChars == 2 && entry->name[0] == 'd' &&
        entry->name[1] >= '0' && entry->name[1] < '0' + CHURN_MAX_DIRS)
    {
        int d = entry->name[1] - '0';
        if (churn_dirs[d])
        {
            ctx->seenDir[d] = TRUE;
            return TRUE;
        }
    }
    for (ULONG i = 0; i < churn_cfg.maxfiles; i++)
    {
        const churn_file *f = &churn_files[i];
        if (!f->inUse || f->dir != ctx->dir || f->nameChars != nameChars)
        {
            continue;
        }
        if (memcmp(f->name, entry->name, nameChars * sizeof(WCHAR)) != 0)
        {
            continue;
        }
        ctx->seen[i] = TRUE;
        ok(entry->info.endOfFile == f->size, "iter %lu: enum %s size %lu want %lu", ctx->iter,
           churn_rel_path(f), (unsigned long)entry->info.endOfFile, (unsigned long)f->size);
        return TRUE;
    }
    ctx->unexpected++;
    ok(0, "iter %lu: unexpected entry in %s (dir %d)", ctx->iter, "churn", ctx->dir);
    return TRUE;
}

static void churn_verify_enum(int dir, ULONG iter)
{
    static churn_enum_ctx ctx; /* bss: seen[] is sizable */
    memset(&ctx, 0, sizeof(ctx));
    ctx.dir = dir;
    ctx.iter = iter;
    NTSTATUS status = IoEnumerateDirectory(churn_nt_path(dir, 0), churn_enum_callback, &ctx);
    ok(status == STATUS_SUCCESS, "iter %lu: enumerate dir %d -> %08lx", iter, dir,
       (unsigned long)status);
    for (ULONG i = 0; i < churn_cfg.maxfiles; i++)
    {
        const churn_file *f = &churn_files[i];
        if (f->inUse && f->dir == dir && !ctx.seen[i])
        {
            ok(0, "iter %lu: %s missing from enumeration", iter, churn_rel_path(f));
        }
    }
    if (dir == -1)
    {
        for (int d = 0; d < CHURN_MAX_DIRS; d++)
        {
            if (churn_dirs[d] && !ctx.seenDir[d])
            {
                ok(0, "iter %lu: d%d missing from enumeration", iter, d);
            }
        }
    }
}

static void churn_verify_tree(ULONG iter)
{
    churn_verify_enum(-1, iter);
    for (int d = 0; d < CHURN_MAX_DIRS; d++)
    {
        if (churn_dirs[d])
        {
            churn_verify_enum(d, iter);
        }
    }
    for (ULONG i = 0; i < churn_cfg.maxfiles; i++)
    {
        if (churn_files[i].inUse)
        {
            churn_verify_file(&churn_files[i], iter);
        }
    }
}

/* --- the generator loop ------------------------------------------------------ */

/* Pick the k-th in-use file slot (deterministic from the shadow). */
static churn_file *churn_pick(ULONG draw)
{
    ULONG used = 0;
    for (ULONG i = 0; i < churn_cfg.maxfiles; i++)
    {
        used += churn_files[i].inUse ? 1 : 0;
    }
    if (used == 0)
    {
        return 0;
    }
    ULONG k = draw % used;
    for (ULONG i = 0; i < churn_cfg.maxfiles; i++)
    {
        if (churn_files[i].inUse && k-- == 0)
        {
            return &churn_files[i];
        }
    }
    return 0;
}

static void churn_new_name(churn_file *f)
{
    static const char alpha[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    ULONG id = churn_name_counter++;
    ULONG a = churn_rng() % 52, b = churn_rng() % 52;
    /* "Churn_NNNNNN_xY.dat": 19 chars, always LFN (case + length). */
    char ascii[CHURN_NAME_CHARS];
    ascii[0] = 'C';
    ascii[1] = 'h';
    ascii[2] = 'u';
    ascii[3] = 'r';
    ascii[4] = 'n';
    ascii[5] = '_';
    for (int i = 0; i < 6; i++)
    {
        ascii[6 + 5 - i] = (char)('0' + id % 10);
        id /= 10;
    }
    ascii[12] = '_';
    ascii[13] = alpha[a];
    ascii[14] = alpha[b];
    ascii[15] = '.';
    ascii[16] = 'd';
    ascii[17] = 'a';
    ascii[18] = 't';
    f->nameChars = 19;
    for (int i = 0; i < 19; i++)
    {
        f->name[i] = (WCHAR)ascii[i];
    }
}

/* One full generator run. wet=TRUE executes against the FS and verifies as
 * it goes; wet=FALSE only advances the shadow (the boot-2 dry replay). */
static void churn_run_model(BOOLEAN wet)
{
    churn_rng_state = churn_cfg.seed;
    memset(churn_files, 0, sizeof(churn_files));
    memset(churn_dirs, 0, sizeof(churn_dirs));
    churn_total_bytes = 0;
    churn_name_counter = 0;
    churn_diskfull = 0;
    uint64_t sizeCap = (uint64_t)churn_cfg.maxsize * 2;

    for (ULONG iter = 1; iter <= churn_cfg.ops; iter++)
    {
        ULONG op = churn_rng() % 100;

        if (op < 18) /* create (or rewrite when the table is full) */
        {
            churn_file *f = 0;
            for (ULONG i = 0; i < churn_cfg.maxfiles && f == 0; i++)
            {
                if (!churn_files[i].inUse)
                {
                    f = &churn_files[i];
                }
            }
            uint64_t size = churn_rng() % (churn_cfg.maxsize + 1);
            ULONG seed = churn_rng();
            ULONG dirDraw = churn_rng();
            if (f == 0)
            {
                churn_file *victim = churn_pick(dirDraw);
                if (victim == 0 || churn_total_bytes - victim->size + size > churn_cfg.budget)
                {
                    continue;
                }
                churn_total_bytes -= victim->size;
                churn_set_whole(victim, size, seed);
                churn_total_bytes += size;
                if (wet &&
                    churn_wet_write(victim, 0, (ULONG)size, seed, FILE_OVERWRITE_IF, iter) != 0)
                {
                    churn_total_bytes -= victim->size;
                    churn_set_whole(victim, 0, 0);
                }
                continue;
            }
            if (churn_total_bytes + size > churn_cfg.budget)
            {
                continue;
            }
            /* Present dirs + the root are candidates. */
            int candidates[CHURN_MAX_DIRS + 1];
            int nc = 0;
            candidates[nc++] = -1;
            for (int d = 0; d < CHURN_MAX_DIRS; d++)
            {
                if (churn_dirs[d])
                {
                    candidates[nc++] = d;
                }
            }
            f->inUse = TRUE;
            f->dir = candidates[dirDraw % (ULONG)nc];
            churn_new_name(f);
            churn_set_whole(f, size, seed);
            churn_total_bytes += size;
            if (wet)
            {
                int outcome = churn_wet_write(f, 0, (ULONG)size, seed, FILE_CREATE, iter);
                if (outcome != 0)
                {
                    churn_total_bytes -= f->size;
                    churn_set_whole(f, 0, 0);
                    if (outcome == 2)
                    {
                        f->inUse = FALSE;
                    }
                }
            }
        }
        else if (op < 30) /* whole-file rewrite */
        {
            uint64_t size = churn_rng() % (churn_cfg.maxsize + 1);
            ULONG seed = churn_rng();
            churn_file *f = churn_pick(churn_rng());
            if (f == 0 || churn_total_bytes - f->size + size > churn_cfg.budget)
            {
                continue;
            }
            churn_total_bytes -= f->size;
            churn_set_whole(f, size, seed);
            churn_total_bytes += size;
            if (wet && churn_wet_write(f, 0, (ULONG)size, seed, FILE_OVERWRITE_IF, iter) != 0)
            {
                churn_total_bytes -= f->size;
                churn_set_whole(f, 0, 0);
            }
        }
        else if (op < 45) /* partial write (may extend past EOF) */
        {
            ULONG offDraw = churn_rng();
            ULONG length = 1 + churn_rng() % 4096;
            ULONG seed = churn_rng();
            churn_file *f = churn_pick(churn_rng());
            if (f == 0)
            {
                continue;
            }
            uint64_t offset = offDraw % (f->size + 4096 + 1);
            if (offset + length > sizeCap)
            {
                offset = sizeCap - length;
            }
            uint64_t newSize = f->size > offset + length ? f->size : offset + length;
            if (churn_total_bytes - f->size + newSize > churn_cfg.budget)
            {
                continue;
            }
            if (!churn_extent_insert(f, offset, offset + length, seed))
            {
                /* Extent table would overflow: degrade to a whole-file
                 * rewrite with the same seed (both sides, deterministic). */
                churn_total_bytes -= f->size;
                churn_set_whole(f, newSize, seed);
                churn_total_bytes += newSize;
                if (wet &&
                    churn_wet_write(f, 0, (ULONG)newSize, seed, FILE_OVERWRITE_IF, iter) != 0)
                {
                    churn_total_bytes -= f->size;
                    churn_set_whole(f, 0, 0);
                }
                continue;
            }
            churn_total_bytes += newSize - f->size;
            f->size = newSize;
            if (wet && churn_wet_write(f, offset, length, seed, FILE_OPEN, iter) != 0)
            {
                churn_total_bytes -= f->size;
                churn_set_whole(f, 0, 0);
            }
        }
        else if (op < 53) /* extend via set-EOF (gap reads as zeros) */
        {
            ULONG grow = 1 + churn_rng() % 8192;
            churn_file *f = churn_pick(churn_rng());
            if (f == 0)
            {
                continue;
            }
            uint64_t newSize = f->size + grow;
            if (newSize > sizeCap)
            {
                newSize = sizeCap;
            }
            if (churn_total_bytes - f->size + newSize > churn_cfg.budget)
            {
                continue;
            }
            uint64_t oldSize = f->size;
            churn_total_bytes += newSize - f->size;
            f->size = newSize;
            if (wet && !churn_wet_seteof(f, newSize, oldSize, iter))
            {
                churn_total_bytes -= newSize - oldSize;
                f->size = oldSize;
            }
        }
        else if (op < 63) /* truncate */
        {
            ULONG draw = churn_rng();
            churn_file *f = churn_pick(churn_rng());
            if (f == 0)
            {
                continue;
            }
            uint64_t newSize = draw % (f->size + 1);
            churn_total_bytes -= f->size - newSize;
            f->size = newSize;
            churn_extent_truncate(f, newSize);
            if (wet)
            {
                churn_wet_seteof(f, newSize, newSize, iter);
            }
        }
        else if (op < 75) /* delete */
        {
            churn_file *f = churn_pick(churn_rng());
            if (f == 0)
            {
                continue;
            }
            if (wet)
            {
                churn_wet_delete(f, iter);
            }
            churn_total_bytes -= f->size;
            f->inUse = FALSE;
        }
        else if (op < 80) /* mkdir / rmdir */
        {
            ULONG draw = churn_rng();
            int d = (int)(draw % CHURN_MAX_DIRS);
            if (!churn_dirs[d])
            {
                churn_dirs[d] = TRUE;
                if (wet)
                {
                    churn_wet_mkdir(d, iter);
                }
            }
            else
            {
                BOOLEAN empty = TRUE;
                for (ULONG i = 0; i < churn_cfg.maxfiles; i++)
                {
                    if (churn_files[i].inUse && churn_files[i].dir == d)
                    {
                        empty = FALSE;
                    }
                }
                if (wet)
                {
                    churn_wet_rmdir(d, empty, iter);
                }
                if (empty)
                {
                    churn_dirs[d] = FALSE;
                }
            }
        }
        else if (op < 90) /* verify one file */
        {
            churn_file *f = churn_pick(churn_rng());
            if (f != 0 && wet)
            {
                churn_verify_file(f, iter);
            }
        }
        else if (op < 98) /* enumerate one directory */
        {
            ULONG draw = churn_rng();
            int d = (int)(draw % (CHURN_MAX_DIRS + 1)) - 1;
            if (wet && (d == -1 || churn_dirs[d]))
            {
                churn_verify_enum(d, iter);
            }
        }
        else /* rename probe */
        {
            churn_file *f = churn_pick(churn_rng());
            if (f != 0 && wet)
            {
                churn_wet_rename_probe(f, iter);
            }
        }

        if (wet && iter % 100 == 0)
        {
            churn_verify_tree(iter);
        }
    }
}

/* --- dump, config, entry ------------------------------------------------------ */

static void churn_dump(void)
{
    DbgPrint("[CHURN] BEGIN seed=%x ops=%lu\n", churn_cfg.seed, (unsigned long)churn_cfg.ops);
    for (int d = 0; d < CHURN_MAX_DIRS; d++)
    {
        if (churn_dirs[d])
        {
            DbgPrint("[CHURN] D churn/d%d\n", d);
        }
    }
    int files = 0, dirs = 0;
    for (int d = 0; d < CHURN_MAX_DIRS; d++)
    {
        dirs += churn_dirs[d] ? 1 : 0;
    }
    for (ULONG i = 0; i < churn_cfg.maxfiles; i++)
    {
        const churn_file *f = &churn_files[i];
        if (!f->inUse)
        {
            continue;
        }
        files++;
        uint32_t crc = 0xFFFFFFFFu;
        uint64_t done = 0;
        while (done < f->size)
        {
            ULONG chunk = f->size - done > 0x10000 ? 0x10000 : (ULONG)(f->size - done);
            churn_model_fill(f, churn_model, done, chunk);
            crc = churn_crc_update(crc, churn_model, chunk);
            done += chunk;
        }
        DbgPrint("[CHURN] F %s %lu %08x\n", churn_rel_path(f), (unsigned long)f->size, ~crc);
    }
    DbgPrint("[CHURN] END files=%d dirs=%d diskfull=%d\n", files, dirs, churn_diskfull);
}

static BOOLEAN churn_load_config(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    init_attr(&attr, &name, WSTR("\\??\\C:\\churn.cfg"));
    NTSTATUS status = NtCreateFile(&handle, FILE_GENERIC_READ, &attr, &iosb, 0,
                                   FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                                   FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }
    char text[256];
    memset(text, 0, sizeof(text));
    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    status = NtReadFile(handle, 0, 0, 0, &iosb, text, sizeof(text) - 1, &offset, 0);
    NtClose(handle);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    /* Defaults, overridden by "key=value" pairs. */
    churn_cfg.seed = 0x1965A11D;
    churn_cfg.ops = 400;
    churn_cfg.maxfiles = 48;
    churn_cfg.maxsize = 16384;
    churn_cfg.budget = 6 * 1024 * 1024;
    churn_cfg.expectDiskFull = FALSE;
    for (char *p = text; *p != 0;)
    {
        while (*p == ' ' || *p == '\n' || *p == '\r')
        {
            p++;
        }
        char *eq = p;
        while (*eq != 0 && *eq != '=')
        {
            eq++;
        }
        if (*eq != '=')
        {
            break;
        }
        uint64_t value = 0;
        char *v = eq + 1;
        if (v[0] == '0' && v[1] == 'x')
        {
            for (v += 2;
                 (*v >= '0' && *v <= '9') || (*v >= 'a' && *v <= 'f') || (*v >= 'A' && *v <= 'F');
                 v++)
            {
                value = value * 16 + (ULONG)(*v <= '9'   ? *v - '0'
                                             : *v >= 'a' ? *v - 'a' + 10
                                                         : *v - 'A' + 10);
            }
        }
        else
        {
            for (; *v >= '0' && *v <= '9'; v++)
            {
                value = value * 10 + (ULONG)(*v - '0');
            }
        }
        switch (*p)
        {
        case 's':
            churn_cfg.seed = (ULONG)value;
            break;
        case 'o':
            churn_cfg.ops = (ULONG)value;
            break;
        case 'm':
            if (p[3] == 'f')
            {
                churn_cfg.maxfiles = (ULONG)value;
            }
            else
            {
                churn_cfg.maxsize = (ULONG)value;
            }
            break;
        case 'b':
            churn_cfg.budget = value;
            break;
        case 'e':
            churn_cfg.expectDiskFull = value != 0;
            break;
        default:
            break;
        }
        p = v;
    }
    if (churn_cfg.maxfiles > CHURN_MAX_FILES)
    {
        churn_cfg.maxfiles = CHURN_MAX_FILES;
    }
    return TRUE;
}

int kmt_run_fat_churn(void)
{
    if (!churn_load_config())
    {
        return 0; /* not a fatstress image */
    }
    int before = kmt_failures;
    DbgPrint("kmt: FAT churn suite (seed=%x ops=%lu maxsize=%lu budget=%lu diskfull=%d)\n",
             churn_cfg.seed, (unsigned long)churn_cfg.ops, (unsigned long)churn_cfg.maxsize,
             (unsigned long)churn_cfg.budget, churn_cfg.expectDiskFull);

    churn_buffer = MiAllocatePool((uint64_t)churn_cfg.maxsize * 2);
    churn_model = MiAllocatePool((uint64_t)churn_cfg.maxsize * 2);
    if (churn_buffer == 0 || churn_model == 0)
    {
        DbgPrint("[KTEST] churn FAIL (pool)\n");
        return 1;
    }

    /* Boot discrimination (the m8_persist hive-absent pattern): the churn
     * directory itself is the marker. */
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    init_attr(&attr, &name, WSTR("\\??\\C:\\churn"));
    NTSTATUS status = NtOpenFile(&handle, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attr, &iosb,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE);
    BOOLEAN seedBoot = !NT_SUCCESS(status);
    if (NT_SUCCESS(status))
    {
        NtClose(handle);
    }

    if (seedBoot)
    {
        status =
            NtCreateFile(&handle, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attr, &iosb, 0,
                         FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE,
                         FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
        ok(status == STATUS_SUCCESS, "create C:\\churn -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            NtClose(handle);
        }
        churn_run_model(TRUE);
        churn_verify_tree(0xFFFF);
        if (churn_cfg.expectDiskFull)
        {
            ok(churn_diskfull > 0, "near-full leg never hit STATUS_DISK_FULL");
        }
        else
        {
            ok(churn_diskfull == 0, "unexpected STATUS_DISK_FULL (%d)", churn_diskfull);
        }
        churn_dump();
        int failures = kmt_failures - before;
        DbgPrint(failures == 0 ? "[KTEST] churn-seed PASS\n"
                               : "[KTEST] churn-seed FAIL failures=%d\n",
                 failures);
        MiFreePool(churn_buffer);
        MiFreePool(churn_model);
        return failures;
    }

    if (churn_cfg.expectDiskFull)
    {
        /* DISK_FULL timing depends on real allocation state: the dry replay
         * cannot reconstruct it. Single-boot legs only. */
        DbgPrint("[KTEST] churn-verify SKIP (diskfull leg)\n");
        MiFreePool(churn_buffer);
        MiFreePool(churn_model);
        return 0;
    }

    /* Boot 2: rebuild the shadow from the seed alone, then verify the tree
     * through a cold cache. */
    churn_run_model(FALSE);
    churn_verify_tree(0);
    churn_dump();
    int failures = kmt_failures - before;
    DbgPrint(failures == 0 ? "[KTEST] churn-verify PASS\n"
                           : "[KTEST] churn-verify FAIL failures=%d\n",
             failures);
    MiFreePool(churn_buffer);
    MiFreePool(churn_model);
    return failures;
}
