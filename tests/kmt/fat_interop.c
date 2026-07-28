/* tests/kmt/fat_interop.c — the FAT interop battery, kernel side (docs/08
 * "The FAT on-disk format has its own oracles").
 *
 * Host->kernel: tests/run/fatgen.py bakes an adversarial corpus with mtools
 * under C:\fatcorpus (LFN unit-boundary and 255-char names, 8.3/case
 * classes, SFN-collision families, cluster- and page-edge sizes, deep
 * nesting, a multi-cluster directory, chains fragmented by host-side FAT
 * surgery) plus a manifest of (type, index, size, fnv32, flags, path). This
 * suite enumerates, opens, reads and checksums all of it through the Nt*
 * surface — every divergence in dir.c's 8.3/LFN logic against an
 * implementation it has never met surfaces here.
 *
 * Kernel->host: the suite then writes the manifest's W battery under
 * C:\fatout through the same Nt* surface; after the boot, the host extracts
 * it with mcopy and verifies names, sizes and content independently
 * (fatgen.py verify).
 *
 * Content is a pure function both sides compute: byte j of file index k is
 * (k*131 + j*7 + 3) & 0xff. The checksum is FNV-1a 32-bit (offset basis
 * 2166136261, prime 16777619 — draft-eastlake-fnv), chosen because it is
 * freestanding-trivial on both sides; the differential comparison itself
 * proves the two implementations agree.
 *
 * Gating: the suite runs only when C:\fatcorpus\manifest.txt exists (the
 * ntapi-sweep "the image decides" pattern) — the run.sh fatinterop leg's
 * image; silently absent everywhere else.
 */
#include "tests/kmt/kmt.h"
#include "kernel/io/io.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/rtl.h"
#include "kernel/lib/string.h"

#include "abi/ntstatus.h"
#include "abi/ntioapi.h"

#define FAT_INTEROP_MANIFEST_MAX (256 * 1024)
#define FAT_INTEROP_PATH_CHARS   280 /* longest corpus rel path + margin */
#define FAT_INTEROP_CHUNK        (64 * 1024)

typedef struct fat_interop_entry
{
    char side; /* 'H' host-baked | 'W' kernel-written */
    char type; /* 'f' | 'd' */
    ULONG index;
    uint64_t size;
    uint32_t fnv;
    BOOLEAN ci;  /* name compares case-insensitively (8.3-only storage) */
    BOOLEAN del; /* W: create then delete; must not exist afterwards */
    BOOLEAN seen;
    USHORT pathChars;
    WCHAR path[FAT_INTEROP_PATH_CHARS]; /* '/'-separated, no leading '/' */
} fat_interop_entry;

static fat_interop_entry *fat_entries;
static int fat_entry_count;
static char *fat_chunk; /* one FAT_INTEROP_CHUNK pool buffer */

static unsigned char fat_content_byte(ULONG index, uint64_t j)
{
    return (unsigned char)((index * 131 + j * 7 + 3) & 0xFF);
}

static uint32_t fnv1a_update(uint32_t h, const void *data, ULONG length)
{
    const unsigned char *p = data;
    for (ULONG i = 0; i < length; i++)
    {
        h = (h ^ p[i]) * 16777619u; /* draft-eastlake-fnv */
    }
    return h;
}
#define FNV_BASIS 2166136261u

static void init_attr(OBJECT_ATTRIBUTES *attr, UNICODE_STRING *name, const WCHAR *path)
{
    RtlInitUnicodeString(name, path);
    memset(attr, 0, sizeof(*attr));
    attr->Length = sizeof(*attr);
    attr->ObjectName = name;
    attr->Attributes = OBJ_CASE_INSENSITIVE;
}

/* Build "\??\C:\<base>\<relPath>" with '/' -> '\'; relPath may be empty.
 * Returns a static buffer (sequential tests, the ntapi-sweep shape). */
static const WCHAR *fat_build_path(const char *base, const WCHAR *rel, USHORT relChars)
{
    static WCHAR path[FAT_INTEROP_PATH_CHARS + 32];
    int n = 0;
    static const WCHAR prefix[] = WSTR("\\??\\C:\\");
    while (prefix[n] != 0)
    {
        path[n] = prefix[n];
        n++;
    }
    for (int i = 0; base[i] != 0; i++)
    {
        path[n++] = (WCHAR)base[i];
    }
    if (relChars != 0)
    {
        path[n++] = '\\';
        for (USHORT i = 0; i < relChars; i++)
        {
            path[n++] = rel[i] == '/' ? (WCHAR)'\\' : rel[i];
        }
    }
    path[n] = 0;
    return path;
}

/* DbgPrint has no %ws: narrow a WCHAR path/name into a static buffer for
 * verdict messages (sequential tests; two slots so one ok() can name two). */
static const char *fat_ascii(const WCHAR *s, USHORT chars)
{
    static char buffers[2][FAT_INTEROP_PATH_CHARS + 1];
    static int slot;
    char *out = buffers[slot ^= 1];
    USHORT n = chars < FAT_INTEROP_PATH_CHARS ? chars : FAT_INTEROP_PATH_CHARS;
    for (USHORT i = 0; i < n; i++)
    {
        out[i] = (s[i] >= 0x20 && s[i] < 0x7F) ? (char)s[i] : '?';
    }
    out[n] = 0;
    return out;
}

static WCHAR fat_lower(WCHAR c)
{
    return (c >= 'A' && c <= 'Z') ? (WCHAR)(c - 'A' + 'a') : c;
}

static BOOLEAN fat_names_equal(const WCHAR *a, USHORT aChars, const WCHAR *b, USHORT bChars,
                               BOOLEAN ci)
{
    if (aChars != bChars)
    {
        return FALSE;
    }
    for (USHORT i = 0; i < aChars; i++)
    {
        if (ci ? fat_lower(a[i]) != fat_lower(b[i]) : a[i] != b[i])
        {
            return FALSE;
        }
    }
    return TRUE;
}

/* --- manifest ---------------------------------------------------------------- */

static BOOLEAN fat_read_manifest_file(UCHAR **bufferOut, ULONG *lengthOut)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    init_attr(&attr, &name, WSTR("\\??\\C:\\fatcorpus\\manifest.txt"));
    NTSTATUS status = NtCreateFile(&handle, FILE_GENERIC_READ, &attr, &iosb, 0,
                                   FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                                   FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }
    BOOLEAN loaded = FALSE;
    FILE_STANDARD_INFORMATION standard;
    status =
        NtQueryInformationFile(handle, &iosb, &standard, sizeof(standard), FileStandardInformation);
    if (NT_SUCCESS(status) && standard.EndOfFile.QuadPart > 0 &&
        standard.EndOfFile.QuadPart <= FAT_INTEROP_MANIFEST_MAX)
    {
        ULONG length = (ULONG)standard.EndOfFile.QuadPart;
        UCHAR *buffer = MiAllocatePool(length);
        if (buffer != 0)
        {
            LARGE_INTEGER offset;
            offset.QuadPart = 0;
            status = NtReadFile(handle, 0, 0, 0, &iosb, buffer, length, &offset, 0);
            if (NT_SUCCESS(status) && iosb.Information == length)
            {
                *bufferOut = buffer;
                *lengthOut = length;
                loaded = TRUE;
            }
            else
            {
                MiFreePool(buffer);
            }
        }
    }
    NtClose(handle);
    return loaded;
}

/* Parse "<side> <type> <index> <size> <fnv8> <flags> <path>" lines (path
 * last: it may contain spaces). Malformed lines are loud — a silently
 * dropped entry would read as "covered". */
static BOOLEAN fat_parse_manifest(const UCHAR *buffer, ULONG length)
{
    /* Pass 1: count parseable lines for the pool allocation. */
    int lines = 0;
    for (ULONG pos = 0; pos < length;)
    {
        if (buffer[pos] != '#' && buffer[pos] != '\n' && buffer[pos] != '\r')
        {
            lines++;
        }
        while (pos < length && buffer[pos] != '\n')
        {
            pos++;
        }
        pos++;
    }
    fat_entries = MiAllocatePool((uint64_t)lines * sizeof(fat_interop_entry));
    if (fat_entries == 0)
    {
        return FALSE;
    }
    memset(fat_entries, 0, (uint64_t)lines * sizeof(fat_interop_entry));
    fat_entry_count = 0;

    for (ULONG pos = 0; pos < length;)
    {
        ULONG end = pos;
        while (end < length && buffer[end] != '\n')
        {
            end++;
        }
        ULONG lineEnd = end;
        while (lineEnd > pos && buffer[lineEnd - 1] == '\r')
        {
            lineEnd--;
        }
        if (lineEnd == pos || buffer[pos] == '#')
        {
            pos = end + 1;
            continue;
        }
        fat_interop_entry *e = &fat_entries[fat_entry_count];
        ULONG p = pos;
        /* side, type */
        if (lineEnd - p < 4)
        {
            return FALSE;
        }
        e->side = (char)buffer[p];
        e->type = (char)buffer[p + 2];
        p += 4;
        /* index (decimal) */
        while (p < lineEnd && buffer[p] != ' ')
        {
            e->index = e->index * 10 + (buffer[p++] - '0');
        }
        p++;
        /* size (decimal) */
        while (p < lineEnd && buffer[p] != ' ')
        {
            e->size = e->size * 10 + (buffer[p++] - '0');
        }
        p++;
        /* fnv (8 hex chars) */
        for (int i = 0; i < 8 && p < lineEnd; i++, p++)
        {
            UCHAR c = buffer[p];
            ULONG nibble = c >= 'a' ? (ULONG)(c - 'a' + 10) : (ULONG)(c - '0');
            e->fnv = (e->fnv << 4) | nibble;
        }
        p++;
        /* flags */
        ULONG flagsStart = p;
        while (p < lineEnd && buffer[p] != ' ')
        {
            p++;
        }
        e->ci = (p - flagsStart == 2 && buffer[flagsStart] == 'c');
        e->del = (p - flagsStart == 3 && buffer[flagsStart] == 'd');
        p++;
        /* path (the rest; ASCII widened to UTF-16) */
        if (p >= lineEnd || lineEnd - p >= FAT_INTEROP_PATH_CHARS)
        {
            DbgPrint("fat_interop: bad manifest line at byte %lu\n", (unsigned long)pos);
            return FALSE;
        }
        e->pathChars = (USHORT)(lineEnd - p);
        for (USHORT i = 0; i < e->pathChars; i++)
        {
            e->path[i] = buffer[p + i];
        }
        if ((e->side != 'H' && e->side != 'W') || (e->type != 'f' && e->type != 'd'))
        {
            DbgPrint("fat_interop: bad manifest line at byte %lu\n", (unsigned long)pos);
            return FALSE;
        }
        fat_entry_count++;
        pos = end + 1;
    }
    return TRUE;
}

/* --- host->kernel: enumerate --------------------------------------------------- */

typedef struct fat_enum_ctx
{
    const WCHAR *dirRel; /* the directory's manifest-relative path ('' = root) */
    USHORT dirRelChars;
    int unexpected;
    int checked;
} fat_enum_ctx;

/* Match one enumerated entry against the manifest H set. */
static BOOLEAN fat_enum_callback(const IO_DIR_ENTRY *entry, PVOID context)
{
    fat_enum_ctx *ctx = context;
    USHORT nameChars = (USHORT)(entry->nameLength / sizeof(WCHAR));

    if ((nameChars == 1 && entry->name[0] == '.') ||
        (nameChars == 2 && entry->name[0] == '.' && entry->name[1] == '.'))
    {
        return TRUE;
    }
    static const WCHAR manifestName[] = WSTR("manifest.txt");
    if (ctx->dirRelChars == 0 && fat_names_equal(entry->name, nameChars, manifestName, 12, TRUE))
    {
        return TRUE;
    }

    /* rel = dirRel '/' name */
    WCHAR rel[FAT_INTEROP_PATH_CHARS];
    USHORT relChars = 0;
    for (USHORT i = 0; i < ctx->dirRelChars; i++)
    {
        rel[relChars++] = ctx->dirRel[i];
    }
    if (ctx->dirRelChars != 0)
    {
        rel[relChars++] = '/';
    }
    for (USHORT i = 0; i < nameChars && relChars < FAT_INTEROP_PATH_CHARS; i++)
    {
        rel[relChars++] = entry->name[i];
    }

    for (int i = 0; i < fat_entry_count; i++)
    {
        fat_interop_entry *e = &fat_entries[i];
        if (e->side != 'H' || !fat_names_equal(rel, relChars, e->path, e->pathChars, e->ci))
        {
            continue;
        }
        e->seen = TRUE;
        ctx->checked++;
        ok((e->type == 'd') == (entry->info.isDirectory != 0), "%s: directory flag mismatch",
           fat_ascii(entry->name, nameChars));
        if (e->type == 'f')
        {
            ok(entry->info.endOfFile == e->size, "%s: enumerated size %lu want %lu",
               fat_ascii(entry->name, nameChars), (unsigned long)entry->info.endOfFile,
               (unsigned long)e->size);
        }
        return TRUE;
    }
    ok(0, "unexpected directory entry '%s' (dir '%s')", fat_ascii(entry->name, nameChars),
       ctx->dirRelChars ? fat_ascii(ctx->dirRel, ctx->dirRelChars) : "<root>");
    ctx->unexpected++;
    return TRUE;
}

static void test_fat_corpus_enumerate(void)
{
    /* The root plus every manifest H directory: no recursion — the manifest
     * itself is the worklist (parents precede children by construction). */
    static const WCHAR empty[1] = {0};
    fat_enum_ctx ctx;
    ctx.dirRel = empty;
    ctx.dirRelChars = 0;
    ctx.unexpected = 0;
    ctx.checked = 0;
    NTSTATUS status =
        IoEnumerateDirectory(fat_build_path("fatcorpus", empty, 0), fat_enum_callback, &ctx);
    ok(status == STATUS_SUCCESS, "enumerate root -> %08lx", (unsigned long)status);

    for (int i = 0; i < fat_entry_count; i++)
    {
        fat_interop_entry *e = &fat_entries[i];
        if (e->side != 'H' || e->type != 'd')
        {
            continue;
        }
        ctx.dirRel = e->path;
        ctx.dirRelChars = e->pathChars;
        status = IoEnumerateDirectory(fat_build_path("fatcorpus", e->path, e->pathChars),
                                      fat_enum_callback, &ctx);
        ok(status == STATUS_SUCCESS, "enumerate '%s' -> %08lx", fat_ascii(e->path, e->pathChars), (unsigned long)status);
    }

    int missing = 0;
    for (int i = 0; i < fat_entry_count; i++)
    {
        if (fat_entries[i].side == 'H' && !fat_entries[i].seen)
        {
            ok(0, "manifest entry never enumerated: %s",
               fat_ascii(fat_entries[i].path, fat_entries[i].pathChars));
            missing++;
        }
    }
    ok(missing == 0 && ctx.unexpected == 0, "%d missing, %d unexpected entries", missing,
       ctx.unexpected);
}

/* --- host->kernel: read + checksum -------------------------------------------- */

static void test_fat_corpus_read(void)
{
    for (int i = 0; i < fat_entry_count; i++)
    {
        fat_interop_entry *e = &fat_entries[i];
        if (e->side != 'H' || e->type != 'f')
        {
            continue;
        }
        UNICODE_STRING name;
        OBJECT_ATTRIBUTES attr;
        IO_STATUS_BLOCK iosb;
        HANDLE handle;
        init_attr(&attr, &name, fat_build_path("fatcorpus", e->path, e->pathChars));
        NTSTATUS status = NtOpenFile(&handle, FILE_GENERIC_READ, &attr, &iosb, FILE_SHARE_READ,
                                     FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
        ok(status == STATUS_SUCCESS, "open %s -> %08lx", fat_ascii(e->path, e->pathChars), (unsigned long)status);
        if (!NT_SUCCESS(status))
        {
            continue;
        }
        uint32_t h = FNV_BASIS;
        uint64_t total = 0;
        BOOLEAN spot = TRUE;
        for (;;)
        {
            LARGE_INTEGER offset;
            offset.QuadPart = (LONGLONG)total;
            status = NtReadFile(handle, 0, 0, 0, &iosb, fat_chunk, FAT_INTEROP_CHUNK, &offset, 0);
            if (status == STATUS_END_OF_FILE || (NT_SUCCESS(status) && iosb.Information == 0))
            {
                break;
            }
            if (!NT_SUCCESS(status))
            {
                ok(0, "read %s at %lu -> %08lx", fat_ascii(e->path, e->pathChars), (unsigned long)total,
                   (unsigned long)status);
                break;
            }
            /* Spot-check the raw bytes against the content formula too, so
             * "two checksum implementations agreeing while both wrong" is
             * ruled out at the ends of the stream. */
            if (total == 0 && iosb.Information > 0 &&
                (unsigned char)fat_chunk[0] != fat_content_byte(e->index, 0))
            {
                spot = FALSE;
            }
            h = fnv1a_update(h, fat_chunk, (ULONG)iosb.Information);
            total += iosb.Information;
            if (iosb.Information < FAT_INTEROP_CHUNK)
            {
                break;
            }
        }
        if (total > 0)
        {
            uint64_t last = total - 1;
            LARGE_INTEGER offset;
            offset.QuadPart = (LONGLONG)last;
            status = NtReadFile(handle, 0, 0, 0, &iosb, fat_chunk, 1, &offset, 0);
            if (!NT_SUCCESS(status) || iosb.Information != 1 ||
                (unsigned char)fat_chunk[0] != fat_content_byte(e->index, last))
            {
                spot = FALSE;
            }
        }
        ok(total == e->size && h == e->fnv && spot,
           "%s: got size=%lu fnv=%08lx spot=%d, want size=%lu fnv=%08lx",
           fat_ascii(e->path, e->pathChars),
           (unsigned long)total, (unsigned long)h, spot, (unsigned long)e->size,
           (unsigned long)e->fnv);
        NtClose(handle);
    }
}

/* --- host->kernel: case-insensitive open -------------------------------------- */

static void test_fat_corpus_case_open(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;

    /* The LFN name 'MixedCase.Dat' opened with the case flipped. */
    init_attr(&attr, &name, WSTR("\\??\\C:\\fatcorpus\\mIXEDcASE.dAT"));
    NTSTATUS status = NtOpenFile(&handle, FILE_GENERIC_READ, &attr, &iosb, FILE_SHARE_READ,
                                 FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    ok(status == STATUS_SUCCESS, "case-flipped open -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        NtClose(handle);
    }

    /* One character off must NOT resolve. */
    init_attr(&attr, &name, WSTR("\\??\\C:\\fatcorpus\\MixedCase.Dot"));
    status = NtOpenFile(&handle, FILE_GENERIC_READ, &attr, &iosb, FILE_SHARE_READ,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "near-miss open -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        NtClose(handle);
    }
}

/* --- kernel->host: the write battery ------------------------------------------ */

static void test_fat_write_battery(void)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;
    HANDLE handle;
    NTSTATUS status;

    /* The output root. */
    init_attr(&attr, &name, WSTR("\\??\\C:\\fatout"));
    status = NtCreateFile(&handle, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attr, &iosb, 0,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                          FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    ok(status == STATUS_SUCCESS, "open C:\\fatout -> %08lx", (unsigned long)status);
    if (NT_SUCCESS(status))
    {
        NtClose(handle);
    }

    for (int i = 0; i < fat_entry_count; i++)
    {
        fat_interop_entry *e = &fat_entries[i];
        if (e->side != 'W')
        {
            continue;
        }
        init_attr(&attr, &name, fat_build_path("fatout", e->path, e->pathChars));
        if (e->type == 'd')
        {
            status = NtCreateFile(&handle, FILE_LIST_DIRECTORY | SYNCHRONIZE, &attr, &iosb, 0,
                                  FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  FILE_OPEN_IF, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                                  0, 0);
            ok(status == STATUS_SUCCESS, "mkdir %s -> %08lx", fat_ascii(e->path, e->pathChars), (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                NtClose(handle);
            }
            continue;
        }

        status = NtCreateFile(&handle, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attr, &iosb, 0,
                              FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
                              FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, 0, 0);
        ok(status == STATUS_SUCCESS, "create %s -> %08lx", fat_ascii(e->path, e->pathChars), (unsigned long)status);
        if (!NT_SUCCESS(status))
        {
            continue;
        }
        uint64_t written = 0;
        while (written < e->size)
        {
            ULONG chunk = (ULONG)(e->size - written < FAT_INTEROP_CHUNK ? e->size - written
                                                                        : FAT_INTEROP_CHUNK);
            for (ULONG j = 0; j < chunk; j++)
            {
                fat_chunk[j] = (char)fat_content_byte(e->index, written + j);
            }
            LARGE_INTEGER offset;
            offset.QuadPart = (LONGLONG)written;
            status = NtWriteFile(handle, 0, 0, 0, &iosb, fat_chunk, chunk, &offset, 0);
            if (!NT_SUCCESS(status) || iosb.Information != chunk)
            {
                ok(0, "write %s at %lu -> %08lx", fat_ascii(e->path, e->pathChars),
                   (unsigned long)written,
                   (unsigned long)status);
                break;
            }
            written += chunk;
        }
        NtClose(handle);

        if (e->del)
        {
            init_attr(&attr, &name, fat_build_path("fatout", e->path, e->pathChars));
            status = NtOpenFile(&handle, DELETE | SYNCHRONIZE, &attr, &iosb,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
            ok(status == STATUS_SUCCESS, "open-for-delete %s -> %08lx", fat_ascii(e->path, e->pathChars),
               (unsigned long)status);
            if (NT_SUCCESS(status))
            {
                FILE_DISPOSITION_INFORMATION disposition;
                disposition.DoDeleteFile = TRUE;
                status = NtSetInformationFile(handle, &iosb, &disposition, sizeof(disposition),
                                              FileDispositionInformation);
                ok(status == STATUS_SUCCESS, "set disposition %s -> %08lx", fat_ascii(e->path, e->pathChars),
                   (unsigned long)status);
                NtClose(handle);
                status = NtOpenFile(&handle, FILE_GENERIC_READ, &attr, &iosb, FILE_SHARE_READ,
                                    FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
                ok(status == STATUS_OBJECT_NAME_NOT_FOUND, "deleted %s -> %08lx", fat_ascii(e->path, e->pathChars),
                   (unsigned long)status);
                if (NT_SUCCESS(status))
                {
                    NtClose(handle);
                }
            }
        }
    }

    /* Negative: a 256-unit final component exceeds the LFN limit
     * (spec section 7: 255 max) — FatCreateEntry must refuse it. */
    {
        static WCHAR longPath[16 + 256 + 1];
        int n = 0;
        static const WCHAR prefix[] = WSTR("\\??\\C:\\fatout\\");
        while (prefix[n] != 0)
        {
            longPath[n] = prefix[n];
            n++;
        }
        for (int i = 0; i < 256; i++)
        {
            longPath[n++] = 'x';
        }
        longPath[n] = 0;
        init_attr(&attr, &name, longPath);
        status = NtCreateFile(&handle, FILE_GENERIC_WRITE, &attr, &iosb, 0, FILE_ATTRIBUTE_NORMAL,
                              0, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
        ok(status == STATUS_OBJECT_NAME_INVALID, "256-char name -> %08lx", (unsigned long)status);
        if (NT_SUCCESS(status))
        {
            NtClose(handle);
        }
    }
}

int kmt_run_fat_interop(void)
{
    UCHAR *manifest;
    ULONG manifestLength;
    if (!fat_read_manifest_file(&manifest, &manifestLength))
    {
        return 0; /* not a fatinterop image (the C:\ntapi precedent) */
    }
    int before = kmt_failures;
    DbgPrint("kmt: FAT interop suite\n");
    if (!fat_parse_manifest(manifest, manifestLength))
    {
        DbgPrint("[KTEST] FATINTEROP FAIL (manifest parse)\n");
        MiFreePool(manifest);
        return 1;
    }
    MiFreePool(manifest);
    fat_chunk = MiAllocatePool(FAT_INTEROP_CHUNK);
    if (fat_chunk == 0)
    {
        DbgPrint("[KTEST] FATINTEROP FAIL (pool)\n");
        return 1;
    }
    DbgPrint("fat_interop: %d manifest entries\n", fat_entry_count);
    KMT_RUN(test_fat_corpus_enumerate);
    KMT_RUN(test_fat_corpus_read);
    KMT_RUN(test_fat_corpus_case_open);
    KMT_RUN(test_fat_write_battery);
    MiFreePool(fat_chunk);
    int failures = kmt_failures - before;
    DbgPrint(failures == 0 ? "[KTEST] FATINTEROP PASS\n" : "[KTEST] FATINTEROP FAIL failures=%d\n",
             failures);
    return failures;
}
