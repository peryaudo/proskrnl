/*
 * user/wtest/crt_sections.c — the .CRT$X?? boundary symbols for the
 * standalone Wine-test links (M10 stretch, Makefile `wtests`).
 *
 * msvcrt/ucrtbase's implib mainCRTStartup (dlls/msvcrt/crt_init.h) walks the
 * initializer tables between __xi_a/__xi_z, __xc_a/__xc_z, __xt_a/__xt_z. In
 * a winegcc link those six symbols come from the winebuild spec object
 * (tools/winebuild/spec32.c output_crt_sections: a zero pointer in
 * .CRT$X?A / .CRT$X?Z, the linker's $-sort placing them around the real
 * entries, e.g. winecrt0's gcc_ctors.c .CRT$XCB/.CRT$XTB). We link without
 * winebuild, so the same shape is replicated here.
 */
typedef int(__cdecl *_PIFV)(void);
typedef void(__cdecl *_PVFV)(void);

__attribute__((section(".CRT$XIA"))) _PIFV __xi_a[1] = {0};
__attribute__((section(".CRT$XIZ"))) _PIFV __xi_z[1] = {0};
__attribute__((section(".CRT$XCA"))) _PVFV __xc_a[1] = {0};
__attribute__((section(".CRT$XCZ"))) _PVFV __xc_z[1] = {0};
__attribute__((section(".CRT$XTA"))) _PVFV __xt_a[1] = {0};
__attribute__((section(".CRT$XTZ"))) _PVFV __xt_z[1] = {0};
