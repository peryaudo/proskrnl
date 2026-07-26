/*
 * dirent.h - the directory walk win32u/freetype.c does over the fonts dir.
 *
 * Three calls, names only: opendir, readdir, closedir. Implemented over
 * NtQueryDirectoryFile in user/wine/win32u/font_unix.c. d_type and the rest
 * of POSIX's dirent are absent because freetype.c reads only d_name; adding
 * fields it does not use would be inventing a contract.
 */
#ifndef PRSK_DIRENT_H
#define PRSK_DIRENT_H

struct dirent
{
    char d_name[260];
};

typedef struct { int opaque; } DIR;

extern DIR *opendir( const char *name );
extern struct dirent *readdir( DIR *dir );
extern int closedir( DIR *dir );

#endif /* PRSK_DIRENT_H */
