/*
 * fcntl.h - open(), for win32u/freetype.c's font files only.
 *
 * Read-only: freetype.c opens fonts to map them and nothing else. The write
 * and create flags exist so the source compiles, not because they work --
 * user/wine/win32u/font_unix.c ignores everything but the path.
 */
#ifndef PRSK_FCNTL_H
#define PRSK_FCNTL_H

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR   2
#define O_CREAT  0x40
#define O_TRUNC  0x200
#define O_BINARY 0

extern int open( const char *name, int flags, ... );
extern int close( int fd );

#endif /* PRSK_FCNTL_H */
