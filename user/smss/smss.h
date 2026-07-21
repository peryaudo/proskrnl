/* user/smss/smss.h — shared helpers between smss.c and firstboot.c (CUI-1). */
#ifndef PROSKRNL_USER_SMSS_H
#define PROSKRNL_USER_SMSS_H

#include "abi/ntdef.h"
#include "abi/ntstatus.h"
#include "abi/ntobapi.h"
#include "abi/ntpsapi.h"
#include "abi/ntpebteb.h"

/* char16_t literal; a bare u"" prefix does not survive clang-format. */
#define WSTR(s) u##s

void smss_say(const char *ascii);
void smss_init_ustr(UNICODE_STRING *str, const WCHAR *wide);

/* firstboot.c: run `wineboot.exe --init` synchronously; returns the exit
 * status to terminate with (0 = machine state populated / already fresh). */
NTSTATUS firstboot_run(void);

#endif /* PROSKRNL_USER_SMSS_H */
