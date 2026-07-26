/*
 * dlfcn.h - the POSIX dynamic-loader surface, over nothing.
 *
 * Three win32u sources load their backends with dlopen(): opengl.c,
 * vulkan.c and freetype.c. The first two have no backend here and must
 * degrade, which they do by themselves when dlopen() returns NULL - that is
 * the same path Wine takes on a host without libGL, so it is exercised
 * upstream rather than invented here.
 *
 * freetype.c is different: FreeType IS present, statically linked
 * (third_party/freetype, built as PE by tools/setup_linux.sh). Rather than
 * teach freetype.c a second way to find its entry points, prsk_dlopen hands
 * back a cookie for the one soname it knows and prsk_dlsym answers from a
 * static name -> address table built out of the linked-in library
 * (user/wine/win32u/freetype_link.c). Everything else fails, loudly enough
 * to read on serial and quietly enough for the caller's own fallback.
 */
#ifndef PRSK_DLFCN_H
#define PRSK_DLFCN_H

#define RTLD_NOW    0x0002
#define RTLD_LAZY   0x0001
#define RTLD_GLOBAL 0x0100
#define RTLD_LOCAL  0x0000

extern void *prsk_dlopen( const char *name, int flags );
extern void *prsk_dlsym( void *handle, const char *symbol );
extern int prsk_dlclose( void *handle );
extern char *prsk_dlerror(void);

#define dlopen(name, flags) prsk_dlopen( (name), (flags) )
#define dlsym(handle, sym)  prsk_dlsym( (handle), (sym) )
#define dlclose(handle)     prsk_dlclose( (handle) )
#define dlerror()           prsk_dlerror()

#endif /* PRSK_DLFCN_H */
