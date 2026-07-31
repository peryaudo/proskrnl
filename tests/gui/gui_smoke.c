/* tests/gui/gui_smoke.c — the GUI-1 acceptance client (docs/02).
 *
 * "Done when: a user program maps the framebuffer and draws a rectangle
 * visible in a screendump; key input is readable."
 *
 * Two independent halves, two independent verdicts, one boot:
 *
 *   [KTEST] gui fb ...     open \Device\Fb0, query the mode, map it with
 *                          plain NtCreateSection + NtMapViewOfSection, and
 *                          paint. The verdict line carries the geometry and
 *                          colours so the host checker never hardcodes them
 *                          (tests/gui/check_rect.py reads them back out).
 *   [KTEST] gui input ...  open \Device\Input0 and block in NtReadFile
 *                          until the harness's QMP `send-key a` arrives.
 *
 * Neither half can run against the Wine oracle -- these are HACK devices
 * (docs/10 HACK-001/002) that NT does not have, so there is nothing to
 * differentially compare a syscall against (the G5 adaptation is written
 * out in docs/03 "GUI-1 notes"). What convicts the framebuffer half is not
 * this program at all: it is QEMU rendering its own scanout back to the
 * host as a PPM, an implementation the kernel does not control (Art. 6).
 *
 * A freestanding PE against ntdll only -- no CRT, no Win32. User clients
 * follow the test-code conventions (Wine style, docs/15 exemption).
 */
/* WIN32_NO_STATUS + <ntstatus.h> is Microsoft's documented dance for the
 * full STATUS_* set (winnt.h alone defines a subset); the ntapi harness
 * (tests/ntapi/ntapi.h) does the same, and the #undef is for mingw-w64,
 * whose ntstatus.h is gated on WIN32_NO_STATUS being unset. */
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include "drivers/fbproto.h"
#include "drivers/hidproto.h"

/* Linux KEY_A. evdev codes are fixed as virtio-input's encoding by virtio
 * 1.2 cs01 §5.8.6; cross-check third_party/qemu
 * include/standard-headers/linux/input-event-codes.h (KEY_A 30). QEMU maps
 * the QMP qcode "a" to exactly this (build/ui/input-keymap-qcode-to-linux.c.inc,
 * Q_KEY_CODE_A -> 0x1e). */
#define KEY_A 30

/* The rectangle. Small enough for any mode Limine is likely to set, offset
 * from the origin so a checker sampling "outside" has somewhere to look. */
#define RECT_X 64
#define RECT_Y 48
#define RECT_W 128
#define RECT_H 96

NTSYSAPI NTSTATUS NTAPI NtDisplayString(UNICODE_STRING *string);
NTSYSAPI NTSTATUS NTAPI NtCreateSection(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *, LARGE_INTEGER *,
                                        ULONG, ULONG, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtMapViewOfSection(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T,
                                           LARGE_INTEGER *, SIZE_T *, ULONG, ULONG, ULONG);
NTSYSAPI NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                              IO_STATUS_BLOCK *, ULONG, PVOID, ULONG, PVOID, ULONG);
NTSYSAPI NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, IO_STATUS_BLOCK *, PVOID,
                                   ULONG, LARGE_INTEGER *, ULONG *);
NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN, LARGE_INTEGER *);

/* The current-process pseudohandle (winternl.h omits the NtCurrentProcess
 * macro; the value is NT's documented (HANDLE)-1). */
#define GUI_CURRENT_PROCESS ((HANDLE)(LONG_PTR) - 1)

/* --- serial output (no CRT; m9_smoke.c's say()) ---------------------------- */

static void say(const char *ascii)
{
    WCHAR wide[160];
    USHORT n = 0;
    UNICODE_STRING string;

    while (ascii[n] != '\0' && n < 159)
    {
        wide[n] = (WCHAR)(unsigned char)ascii[n];
        n++;
    }
    string.Length = (USHORT)(n * sizeof(WCHAR));
    string.MaximumLength = string.Length;
    string.Buffer = wide;
    NtDisplayString(&string);
}

static char *append_text(char *out, const char *text)
{
    while (*text)
        *out++ = *text++;
    return out;
}

static char *append_number(char *out, ULONGLONG value, unsigned int base, unsigned int pad)
{
    char digits[24];
    unsigned int n = 0;

    do
    {
        unsigned int digit = (unsigned int)(value % base);
        digits[n++] = (char)(digit < 10 ? '0' + digit : 'a' + digit - 10);
        value /= base;
    } while (value != 0);

    while (n < pad)
        digits[n++] = '0';
    while (n--)
        *out++ = digits[n];
    return out;
}

/* --- the framebuffer half --------------------------------------------------- */

static void open_device(const WCHAR *path, ACCESS_MASK access, HANDLE *handle, NTSTATUS *status)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK iosb;

    RtlInitUnicodeString(&name, path);
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    *handle = NULL;
    *status =
        NtCreateFile(handle, access | SYNCHRONIZE, &attributes, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                     0 /* exclusive */, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

static void fail(const char *what, NTSTATUS status)
{
    char line[160];
    char *out = line;

    out = append_text(out, "[KTEST] gui ");
    out = append_text(out, what);
    out = append_text(out, " FAIL (");
    out = append_number(out, (ULONGLONG)(ULONG)status, 16, 8);
    out = append_text(out, ")\r\n");
    *out = '\0';
    say(line);
}

/* Pack one colour for this mode's pixel layout — never an assumed BGRA. */
static ULONG pack_pixel(const FB_MODE_INFO *mode, ULONG red, ULONG green, ULONG blue)
{
    return (red << mode->redMaskShift) | (green << mode->greenMaskShift) |
           (blue << mode->blueMaskShift);
}

static int test_framebuffer(void)
{
    HANDLE fb, section = NULL;
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    FB_MODE_INFO mode;
    PVOID view = NULL;
    SIZE_T viewSize = 0;
    ULONG background, foreground;
    char line[200];
    char *out;

    open_device(L"\\Device\\Fb0", FILE_GENERIC_READ | FILE_GENERIC_WRITE, &fb, &status);
    if (!NT_SUCCESS(status))
    {
        fail("fb", status);
        return 1;
    }

    status = NtDeviceIoControlFile(fb, NULL, NULL, NULL, &iosb, IOCTL_PRSFB_GET_MODE, NULL, 0,
                                   &mode, sizeof(mode));
    if (!NT_SUCCESS(status))
    {
        fail("fb", status);
        return 1;
    }

    /* A write that would EXTEND the scanout must be refused, not dispatched.
     * FbOps has a GetCache but no SetEndOfFile -- the mode is fixed -- and
     * kernel/io/rw.c called ops->SetEndOfFile unchecked whenever a write
     * passed EOF, so this was a call through a NULL pointer in ring 0: a #PF
     * with CS.RPL == 0, which KiDispatchTrap does not contain, i.e. KiPanic
     * from an unprivileged process. FbCreate does not filter grantedAccess,
     * so the writable handle above is all it took.
     *
     * Same documented contract as the input-write case below
     * (STATUS_INVALID_DEVICE_REQUEST for a major function the device does not
     * implement); no oracle leg exists for a HACK device. The write starts
     * one byte inside the scanout so only its TAIL is past the end -- that is
     * the shape that reaches the resize path rather than a bounds check. */
    {
        LARGE_INTEGER past;
        BYTE two[2] = {0, 0};
        past.QuadPart = (LONGLONG)mode.pitch * mode.height - 1;
        NTSTATUS extend = NtWriteFile(fb, NULL, NULL, NULL, &iosb, two, sizeof(two), &past, NULL);
        if (extend != STATUS_INVALID_DEVICE_REQUEST)
        {
            fail("fb-extend", extend);
            return 1;
        }
    }
    if (mode.bpp != 32 || mode.memoryModel != FB_MEMORY_MODEL_RGB)
    {
        fail("fb", STATUS_NOT_SUPPORTED);
        return 1;
    }
    if (mode.width < RECT_X + RECT_W || mode.height < RECT_Y + RECT_H)
    {
        fail("fb", STATUS_BUFFER_TOO_SMALL);
        return 1;
    }

    /* The mapping the milestone asks for, through the ordinary NT path:
     * a data section over the device handle, mapped shared. */
    status =
        NtCreateSection(&section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READWRITE, SEC_COMMIT, fb);
    if (!NT_SUCCESS(status))
    {
        fail("fb", status);
        return 1;
    }
    status = NtMapViewOfSection(section, GUI_CURRENT_PROCESS, &view, 0, 0, NULL, &viewSize, 2, 0,
                                PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        fail("fb", status);
        return 1;
    }
    if (viewSize < mode.size)
    {
        fail("fb", STATUS_BUFFER_TOO_SMALL);
        return 1;
    }

    background = pack_pixel(&mode, 0x00, 0x00, 0xFF);
    foreground = pack_pixel(&mode, 0xFF, 0x00, 0x00);

    for (ULONG y = 0; y < mode.height; y++)
    {
        ULONG *row = (ULONG *)((UCHAR *)view + (ULONGLONG)y * mode.pitch);
        for (ULONG x = 0; x < mode.width; x++)
            row[x] = background;
    }
    for (ULONG y = RECT_Y; y < RECT_Y + RECT_H; y++)
    {
        ULONG *row = (ULONG *)((UCHAR *)view + (ULONGLONG)y * mode.pitch);
        for (ULONG x = RECT_X; x < RECT_X + RECT_W; x++)
            row[x] = foreground;
    }

    /* The verdict line IS the checker's input: geometry and colours come
     * from the guest, so the host never assumes a mode QEMU might change. */
    out = line;
    out = append_text(out, "[KTEST] gui fb drawn w=");
    out = append_number(out, mode.width, 10, 0);
    out = append_text(out, " h=");
    out = append_number(out, mode.height, 10, 0);
    out = append_text(out, " pitch=");
    out = append_number(out, mode.pitch, 10, 0);
    out = append_text(out, " rect=");
    out = append_number(out, RECT_X, 10, 0);
    out = append_text(out, ",");
    out = append_number(out, RECT_Y, 10, 0);
    out = append_text(out, ",");
    out = append_number(out, RECT_W, 10, 0);
    out = append_text(out, "x");
    out = append_number(out, RECT_H, 10, 0);
    out = append_text(out, " fg=ff0000 bg=0000ff\r\n");
    *out = '\0';
    say(line);
    return 0;
}

/* --- the input half --------------------------------------------------------- */

static int test_input(void)
{
    HANDLE input;
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    HID_INPUT_EVENT events[32];
    int sawPress = 0;
    unsigned int scanned = 0;

    /* Writing to an input stream must be REFUSED, not dispatched. HidInputOps
     * has a Read and no Write, and no GetCache either -- and kernel/io/rw.c
     * only entered its device branch when ops->Write was non-NULL, falling
     * through to an unchecked ops->GetCache(...) call otherwise. HidInputCreate
     * does not filter grantedAccess, so a FILE_GENERIC_WRITE open succeeds and
     * NtWriteFile's own access gate passes: the result was a call through a
     * NULL function pointer in ring 0, i.e. a #PF with CS.RPL == 0, which
     * KiDispatchTrap does not contain -- KiPanic, from an unprivileged
     * process.
     *
     * STATUS_INVALID_DEVICE_REQUEST is what NT returns when a device does not
     * implement the requested operation (Microsoft, "NTSTATUS values" /
     * IRP_MJ_WRITE: a driver with no dispatch routine for a major function
     * completes the IRP with this status). There is no oracle leg here at all
     * -- \Device\Input0 is HACK-002 (docs/10), which NT does not have -- so
     * this is pinned against that documented contract.
     *
     * This runs BEFORE the read handle is opened: open_device asks for
     * exclusive share access, so a second handle on the same device would
     * fail with a sharing violation and silently skip the case. */
    {
        HANDLE writable = NULL;
        NTSTATUS wstatus;
        open_device(L"\\Device\\Input0", FILE_GENERIC_READ | FILE_GENERIC_WRITE, &writable,
                    &wstatus);
        if (!NT_SUCCESS(wstatus))
        {
            fail("input-write-open", wstatus);
            return 1;
        }
        {
            IO_STATUS_BLOCK wiosb;
            HID_INPUT_EVENT bogus;
            memset(&bogus, 0, sizeof(bogus));
            wstatus = NtWriteFile(writable, NULL, NULL, NULL, &wiosb, &bogus, sizeof(bogus), NULL,
                                  NULL);
            NtClose(writable);
            if (wstatus != STATUS_INVALID_DEVICE_REQUEST)
            {
                fail("input-write", wstatus);
                return 1;
            }
        }
    }

    open_device(L"\\Device\\Input0", FILE_GENERIC_READ, &input, &status);
    if (!NT_SUCCESS(status))
    {
        fail("input", status);
        return 1;
    }

    /* The harness waits for this line before injecting the key, so the
     * press cannot race the open. */
    say("[KTEST] gui input READY\r\n");

    /* Bounded: a device that streams events but never the one we asked for
     * must fail loudly rather than hang until the harness deadline. */
    while (scanned < 256)
    {
        status = NtReadFile(input, NULL, NULL, NULL, &iosb, events, sizeof(events), NULL, NULL);
        if (!NT_SUCCESS(status))
        {
            fail("input", status);
            return 1;
        }
        for (ULONG i = 0; i < iosb.Information / sizeof(HID_INPUT_EVENT); i++)
        {
            scanned++;
            if (events[i].type != HID_EV_KEY || events[i].code != KEY_A)
                continue; /* EV_SYN report boundaries and any other key */
            if (events[i].value == 1)
                sawPress = 1;
            else if (events[i].value == 0 && sawPress)
            {
                say("[KTEST] gui input PASS\r\n");
                return 0;
            }
        }
    }
    fail("input", STATUS_TIMEOUT);
    return 1;
}

void gui_start(void *peb)
{
    (void)peb;

    if (test_framebuffer() == 0)
        say("[KTEST] gui fb PASS\r\n");
    test_input();

    /* Never exit: the framebuffer must still hold the drawing when the host
     * takes its screendump, and a process teardown here would race it. The
     * harness ends the guest with QMP `quit` once both verdicts are in. */
    for (;;)
    {
        LARGE_INTEGER interval;
        interval.QuadPart = -10000000LL; /* 1 s, relative */
        NtDelayExecution(FALSE, &interval);
    }
}
