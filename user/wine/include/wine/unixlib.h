/*
 * wine/unixlib.h - shadows the pinned tree's copy, to re-spell __TRY.
 *
 * Found before third_party/wine/include because -Iuser/wine/include comes
 * first; the real header is pulled in unchanged through #include_next, so
 * this adds to it rather than forking it.
 *
 * The one thing that does not survive compiling win32u's unix half as PE
 * (GUI-2) is its exception macros. On unix they are a setjmp trampoline over
 * ntdll_set_exception_jmp_buf, because unix code has no SEH frame to hang a
 * handler on; PE code does, and proskrnl already runs Wine's PE flavour of
 * these macros (kernelbase's own __TRY, user/hello/hello_seh.S). So the unix
 * definitions are dropped and wine/exception.h's are taken instead, with
 * their handlers coming from the pinned tree's own libwinecrt0.a.
 *
 * Three sources spell a bare __EXCEPT (font.c, defwnd.c, dibdrv/dc.c) where
 * the PE macro expects a filter function. __EXCEPT_ALL is what the unix
 * macro means - catch everything - so that is what it maps to. No win32u
 * source uses the filter form, so nothing is shadowed.
 *
 * Included at its natural point in each source rather than forced onto the
 * command line: unixlib.h redirects wcstol/wcsspn/... to its own inline
 * versions, and pulling it in ahead of the system headers makes those
 * redirections collide with the real declarations.
 */
#ifndef PRSK_WINE_UNIXLIB_H
#define PRSK_WINE_UNIXLIB_H

#include_next <wine/unixlib.h>

#if defined(WINE_UNIX_LIB) && defined(__WINESRC__)

#undef __TRY
#undef __EXCEPT
#undef __ENDTRY

#include <wine/exception.h>

#undef __EXCEPT
#define __EXCEPT __EXCEPT_ALL

#endif /* WINE_UNIX_LIB && __WINESRC__ */

#endif /* PRSK_WINE_UNIXLIB_H */
