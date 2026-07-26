/*
 * sys/types.h - the POSIX id types wineserver's security.h names.
 *
 * mingw has a sys/types.h but no uid_t/gid_t; server/security.h declares
 * `token_sid_present( ..., uid_t )`-shaped helpers unconditionally. The
 * GUI-2 build never runs the unix-credential paths (there is no unix), so
 * only the spelling has to exist. Wrapping mingw's own header keeps the rest
 * of it (size_t, off_t, ssize_t) intact.
 */
#ifndef PRSK_SYS_TYPES_H
#define PRSK_SYS_TYPES_H

#include_next <sys/types.h>

typedef int uid_t;
typedef int gid_t;

#endif /* PRSK_SYS_TYPES_H */
