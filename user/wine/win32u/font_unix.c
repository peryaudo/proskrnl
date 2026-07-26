/*
 * font_unix.c - the file calls win32u's font backend makes, over Nt*.
 *
 * dlls/win32u/freetype.c enumerates and maps font files the unix way: it
 * asks ntdll for a font's unix path, opens it, fstats it and mmaps it
 * (map_font_file), and it walks the fonts directory with opendir/readdir.
 * Nine calls in total, all read-only, all on ordinary files.
 *
 * Compiled as PE there is no unix path and no descriptor table, so this
 * file provides both: "unix paths" ARE NT paths here (ntdll_get_unix_file_name
 * hands back the NT spelling of the DOS name and ntdll_get_dos_file_name
 * reverses it), descriptors are small integers indexing a table of NT
 * handles, and mmap is NtCreateSection + NtMapViewOfSection over the file --
 * the same pair \Device\Fb0 is mapped with.
 *
 * Nothing here is a general POSIX layer and it must not become one. Writing,
 * seeking, anonymous mappings and directory creation have no caller in
 * freetype.c and are absent rather than approximated.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dirent.h>
#include <fcntl.h>

#include "ntstatus.h"
#include "win32u_private.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(font);

/* --- descriptors ----------------------------------------------------------
 *
 * freetype.c holds at most a handful open at once (it maps a file and closes
 * the descriptor immediately), so a fixed table is enough and its exhaustion
 * is a bug worth hearing about rather than a limit to grow past. */

#define PRSK_MAX_FDS 32

static HANDLE fd_table[PRSK_MAX_FDS];
static pthread_mutex_t fd_lock = PTHREAD_MUTEX_INITIALIZER;

static int fd_add( HANDLE handle )
{
    int i;

    pthread_mutex_lock( &fd_lock );
    for (i = 0; i < PRSK_MAX_FDS; i++)
    {
        if (fd_table[i]) continue;
        fd_table[i] = handle;
        pthread_mutex_unlock( &fd_lock );
        return i + 1;   /* 0 would look like stdin */
    }
    pthread_mutex_unlock( &fd_lock );
    ERR( "out of font descriptors\n" );
    NtClose( handle );
    return -1;
}

static HANDLE fd_get( int fd )
{
    if (fd < 1 || fd > PRSK_MAX_FDS) return NULL;
    return fd_table[fd - 1];
}

/* --- paths ----------------------------------------------------------------
 *
 * On Wine these convert between a DOS path and the unix file behind it.
 * There is no unix file, and there is nothing below the NT namespace to
 * convert to, so the "unix name" is the NT name: C:\windows\fonts\x.ttf
 * becomes \??\C:\windows\fonts\x.ttf, and back. The conversion is total and
 * reversible, which is all freetype.c relies on -- it treats the result as
 * an opaque token to hand back to open(). */

NTSTATUS ntdll_get_unix_file_name( const WCHAR *dos, char **unix_name, UINT disposition )
{
    static const char prefix[] = "\\??\\";
    size_t skip = sizeof(prefix) - 1, len = wcslen( dos );
    char *name;
    size_t i;

    /* Not every caller hands a drive-letter path: font.c composes paths
     * from ntdll_get_data_dir, which here already IS the NT spelling, so
     * they arrive with the \??\ prefix in place. Adding a second one made
     * every font open fail (and so every select_font bail). */
    if (len < skip || dos[0] != '\\' || dos[1] != '?' || dos[2] != '?' || dos[3] != '\\')
        skip = 0;

    if (!(name = malloc( sizeof(prefix) + len ))) return STATUS_NO_MEMORY;
    memcpy( name, prefix, sizeof(prefix) - 1 );
    dos += skip;
    len -= skip;
    /* Font paths are ASCII on this image (the baked fonts directory); a
     * non-ASCII name would be silently mangled, so refuse it instead. */
    for (i = 0; i < len; i++)
    {
        if (dos[i] > 0x7f)
        {
            free( name );
            WARN( "non-ASCII font path %s\n", debugstr_w(dos) );
            return STATUS_OBJECT_NAME_INVALID;
        }
        name[sizeof(prefix) - 1 + i] = (char)dos[i];
    }
    name[sizeof(prefix) - 1 + len] = 0;
    *unix_name = name;
    return STATUS_SUCCESS;
}

NTSTATUS ntdll_get_dos_file_name( const char *unix_name, WCHAR **dos, UINT disposition )
{
    const char *source = unix_name;
    size_t len, i;
    WCHAR *name;

    if (!strncmp( source, "\\??\\", 4 )) source += 4;
    len = strlen( source );
    if (!(name = malloc( (len + 1) * sizeof(WCHAR) ))) return STATUS_NO_MEMORY;
    for (i = 0; i < len; i++) name[i] = (unsigned char)source[i];
    name[len] = 0;
    *dos = name;
    return STATUS_SUCCESS;
}

/* --- the file calls -------------------------------------------------------- */

static HANDLE open_nt_path( const char *name, ULONG options )
{
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    HANDLE handle = NULL;
    size_t len = strlen( name ), i;
    WCHAR *wide;

    if (!(wide = malloc( (len + 1) * sizeof(WCHAR) ))) return NULL;
    for (i = 0; i < len; i++) wide[i] = (unsigned char)name[i];
    wide[len] = 0;

    path.Buffer = wide;
    path.Length = len * sizeof(WCHAR);
    path.MaximumLength = path.Length + sizeof(WCHAR);
    InitializeObjectAttributes( &attr, &path, OBJ_CASE_INSENSITIVE, NULL, NULL );
    if (NtOpenFile( &handle, FILE_GENERIC_READ, &attr, &io,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, options ))
        handle = NULL;
    free( wide );
    return handle;
}

int open( const char *name, int flags, ... )
{
    HANDLE handle = open_nt_path( name, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE );

    if (!handle) return -1;
    return fd_add( handle );
}

int close( int fd )
{
    HANDLE handle = fd_get( fd );

    if (!handle) return -1;
    fd_table[fd - 1] = NULL;
    NtClose( handle );
    return 0;
}

int fstat( int fd, struct stat *out )
{
    FILE_STANDARD_INFORMATION info;
    FILE_INTERNAL_INFORMATION internal;
    IO_STATUS_BLOCK io;
    HANDLE handle = fd_get( fd );

    if (!handle) return -1;
    if (NtQueryInformationFile( handle, &io, &info, sizeof(info), FileStandardInformation ))
        return -1;

    memset( out, 0, sizeof(*out) );
    out->st_size = info.EndOfFile.QuadPart;
    out->st_mode = 0100444;
    /* map_font_file keys its cache on (dev, ino) to notice that two names
     * are the same file. The NT file id is exactly that identity, so it
     * stands in for the inode; there is one volume, so the device is
     * constant. */
    if (!NtQueryInformationFile( handle, &io, &internal, sizeof(internal),
                                 FileInternalInformation ))
        out->st_ino = internal.IndexNumber.QuadPart;
    out->st_dev = 1;
    return 0;
}

int stat( const char *name, struct stat *out )
{
    int fd = open( name, 0 ), ret;

    if (fd < 0) return -1;
    ret = fstat( fd, out );
    close( fd );
    return ret;
}

void *mmap( void *addr, size_t length, int prot, int flags, int fd, off_t offset )
{
    HANDLE handle = fd_get( fd ), section;
    void *view = NULL;
    SIZE_T size = 0;
    LARGE_INTEGER at;

    if (!handle || offset) return MAP_FAILED;
    if (NtCreateSection( &section, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_COMMIT,
                         handle ))
        return MAP_FAILED;
    at.QuadPart = 0;
    if (NtMapViewOfSection( section, GetCurrentProcess(), &view, 0, 0, &at, &size, ViewShare, 0,
                            PAGE_READONLY ))
        view = MAP_FAILED;
    /* The view keeps the section alive; freetype.c holds the mapping for the
     * life of the font, and drops it with munmap. */
    NtClose( section );
    return view;
}

int munmap( void *addr, size_t length )
{
    return NtUnmapViewOfSection( GetCurrentProcess(), addr ) ? -1 : 0;
}

/* --- directories -----------------------------------------------------------
 *
 * One directory is open at a time (freetype.c walks the fonts directory to
 * find what to add), and it reads names only. The whole listing is taken in
 * one NtQueryDirectoryFile pass so that readdir cannot fail halfway through
 * with nowhere to report it. */

struct prsk_dir
{
    DIR             handle;     /* the opaque DIR the caller holds */
    struct dirent   entry;
    char           *names;      /* NUL-separated */
    size_t          size;
    size_t          position;
};

DIR *opendir( const char *name )
{
    IO_STATUS_BLOCK io;
    struct prsk_dir *dir;
    HANDLE handle;
    char buffer[4096];
    size_t used = 0, capacity = 0;
    char *names = NULL;

    if (!(handle = open_nt_path( name, FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE )))
        return NULL;

    while (!NtQueryDirectoryFile( handle, NULL, NULL, NULL, &io, buffer, sizeof(buffer),
                                  FileBothDirectoryInformation, FALSE, NULL, FALSE ))
    {
        FILE_BOTH_DIRECTORY_INFORMATION *info = (FILE_BOTH_DIRECTORY_INFORMATION *)buffer;

        for (;;)
        {
            ULONG i, length = info->FileNameLength / sizeof(WCHAR);

            if (used + length + 1 > capacity)
            {
                size_t want = capacity ? capacity * 2 : 4096;
                char *bigger;

                while (want < used + length + 1) want *= 2;
                if (!(bigger = realloc( names, want ))) goto failed;
                names = bigger;
                capacity = want;
            }
            for (i = 0; i < length; i++)
                names[used++] = (info->FileName[i] > 0x7f) ? '?' : (char)info->FileName[i];
            names[used++] = 0;

            if (!info->NextEntryOffset) break;
            info = (FILE_BOTH_DIRECTORY_INFORMATION *)((char *)info + info->NextEntryOffset);
        }
    }
    NtClose( handle );

    if (!(dir = calloc( 1, sizeof(*dir) ))) goto failed;
    dir->names = names;
    dir->size = used;
    return (DIR *)dir;

failed:
    NtClose( handle );
    free( names );
    return NULL;
}

struct dirent *readdir( DIR *handle )
{
    struct prsk_dir *dir = (struct prsk_dir *)handle;
    const char *name;
    size_t length;

    if (!dir || dir->position >= dir->size) return NULL;
    name = dir->names + dir->position;
    length = strlen( name );
    dir->position += length + 1;

    if (length >= sizeof(dir->entry.d_name)) return readdir( handle );  /* too long to name */
    memcpy( dir->entry.d_name, name, length + 1 );
    return &dir->entry;
}

int closedir( DIR *handle )
{
    struct prsk_dir *dir = (struct prsk_dir *)handle;

    if (!dir) return -1;
    free( dir->names );
    free( dir );
    return 0;
}
