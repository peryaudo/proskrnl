/*
 * sys/stat.h - the two fields win32u/freetype.c reads off a font file.
 *
 * map_font_file keys its cache on (st_dev, st_ino) so that two names for
 * one file share a mapping, and reads st_size to know how much to map.
 * Implemented over NtQueryInformationFile in user/wine/win32u/font_unix.c,
 * where the NT file id stands in for the inode.
 *
 * Deliberately NOT mingw's sys/stat.h: that one declares stat() against
 * msvcrt's struct, whose layout has no inode at all.
 */
#ifndef PRSK_SYS_STAT_H
#define PRSK_SYS_STAT_H

#include <sys/types.h>

struct stat
{
    unsigned long long st_dev;
    unsigned long long st_ino;
    unsigned int       st_mode;
    long long          st_size;
};

extern int stat( const char *name, struct stat *out );
extern int fstat( int fd, struct stat *out );

#endif /* PRSK_SYS_STAT_H */
