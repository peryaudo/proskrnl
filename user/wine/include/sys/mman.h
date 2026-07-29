/*
 * sys/mman.h - the file-mapping calls win32u/freetype.c makes.
 *
 * freetype.c maps each font file once and hands FreeType the bytes
 * (map_font_file), so the two calls it needs are mmap of a whole file and
 * munmap. Implemented over NtCreateSection/NtMapViewOfSection in
 * user/wine/dlls/win32u/font_unix.c - the same pair \Device\Fb0 is mapped with.
 * Nothing else here is honoured: anonymous mappings, MAP_FIXED and
 * protection changes have no caller and would be inventing semantics.
 */
#ifndef PRSK_SYS_MMAN_H
#define PRSK_SYS_MMAN_H

#include <sys/types.h>

#define PROT_NONE  0x0
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

#define MAP_SHARED  0x01
#define MAP_PRIVATE 0x02
#define MAP_FAILED  ((void *)-1)

extern void *mmap( void *addr, size_t length, int prot, int flags, int fd, off_t offset );
extern int munmap( void *addr, size_t length );

#endif /* PRSK_SYS_MMAN_H */
