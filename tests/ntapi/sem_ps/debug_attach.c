/*
 * sem_ps/debug_attach.c — debugger ATTACH, and nothing else (WOW64 milestone).
 *
 * ADR 0011 declared the debug port out of scope. The WOW64 milestone re-opens
 * exactly one corner of it and no more: ntdll:wow64 calls DebugActiveProcess
 * on its 32-bit child and then reads BeingDebugged out of BOTH PEBs, so the
 * attach path is a front-door consumer of a boundary behavior rather than a
 * feature anyone asked for. The amendment carves out the three calls that
 * attach makes and leaves the EVENT QUEUE unbuilt:
 *
 *   DebugActiveProcess -> DbgUiConnectToDbg -> NtCreateDebugObject
 *                      -> DbgUiDebugActiveProcess -> NtDebugActiveProcess
 *   DebugActiveProcessStop -> DbgUiStopDebugging -> NtRemoveProcessDebug
 *
 * (third_party/wine dlls/kernelbase/debug.c, dlls/ntdll/process.c.)
 *
 * What this pin measures is therefore the OBSERVABLE effect of attaching —
 * the BeingDebugged byte flipping in the target's PEB and back — plus the
 * statuses of the refusals around it. NtWaitForDebugEvent and NtDebugContinue
 * are deliberately not exercised: they stay unbuilt and loud (Art. 12), and a
 * test asserting STATUS_NOT_IMPLEMENTED for them would be pinning "unbuilt"
 * as an answer, which G12 forbids.
 *
 * Oracle-first (G5): every assert here is measured on the pinned Wine.
 */
#include "util.h"

#include <string.h> /* declarations only: the .exe links no CRT (ntapi.c) */

/* wine/include/winternl.h: the debug-object calls mingw's headers omit. */
NTSYSAPI NTSTATUS NTAPI NtCreateDebugObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
NTSYSAPI NTSTATUS NTAPI NtDebugActiveProcess(HANDLE, HANDLE);
NTSYSAPI NTSTATUS NTAPI NtRemoveProcessDebug(HANDLE, HANDLE);

/* wine/include/winternl.h DEBUG_KILL_ON_CLOSE; DEBUG_ALL_ACCESS is the
 * standard-rights-required | 0x1f form DbgUiConnectToDbg asks for. */
#define PS_DEBUG_KILL_ON_CLOSE 0x1
#define PS_DEBUG_ALL_ACCESS    (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1f)

/* PEB.BeingDebugged is the second byte of the PEB (wine/include/winternl.h
 * PEB: InheritedAddressSpace, ReadImageFileExecOptions, BeingDebugged). */
#define PEB_BEING_DEBUGGED 0x002

static BYTE peb_byte(HANDLE process, ULONG_PTR peb, ULONG offset)
{
    BYTE value = 0xcc;
    SIZE_T res = 0;
    if (!ReadProcessMemory(process, (void *)(peb + offset), &value, sizeof(value), &res) ||
        res != sizeof(value))
    {
        return 0xcc;
    }
    return value;
}

START_TEST(debug_attach)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    NTSTATUS status;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    /* --- the debug object ---------------------------------------------- */
    OBJECT_ATTRIBUTES attr;
    memset(&attr, 0, sizeof(attr));
    attr.Length = sizeof(attr);
    HANDLE debugObject = NULL;
    status = NtCreateDebugObject(&debugObject, PS_DEBUG_ALL_ACCESS, &attr, PS_DEBUG_KILL_ON_CLOSE);
    ok(status == STATUS_SUCCESS, "NtCreateDebugObject -> %08lx", (unsigned long)status);
    ok(debugObject != NULL, "no debug object handle");
    if (!NT_SUCCESS(status))
    {
        skip("no debug object to attach with");
        return;
    }

    BOOL created = CreateProcessA("C:\\windows\\system32\\cmd.exe", NULL, NULL, NULL, FALSE,
                                  CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    ok(created, "CreateProcessA(cmd.exe) -> %lu", (unsigned long)GetLastError());
    if (!created)
    {
        CloseHandle(debugObject);
        skip("no child to attach to");
        return;
    }

    PROCESS_BASIC_INFORMATION basic;
    memset(&basic, 0, sizeof(basic));
    status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &basic, sizeof(basic),
                                       NULL);
    ok(status == STATUS_SUCCESS, "ProcessBasicInformation -> %08lx", (unsigned long)status);
    ULONG_PTR peb = (ULONG_PTR)basic.PebBaseAddress;

    ok(peb_byte(pi.hProcess, peb, PEB_BEING_DEBUGGED) == 0, "BeingDebugged set before attach");

    /* --- attach: the whole observable effect --------------------------- */
    status = NtDebugActiveProcess(pi.hProcess, debugObject);
    ok(status == STATUS_SUCCESS, "NtDebugActiveProcess -> %08lx", (unsigned long)status);
    ok(peb_byte(pi.hProcess, peb, PEB_BEING_DEBUGGED) == 1, "BeingDebugged clear after attach");

    /* Attaching twice is refused rather than silently succeeding. The
     * STATUS is measured, not assumed: the oracle answers ACCESS_DENIED
     * where NT's documentation says STATUS_PORT_ALREADY_SET. proskrnl
     * matches the ORACLE, because the oracle is what the winetest pair is
     * differenced against (Art. 6) — a kernel answering the documented
     * status would make ntdll:wow64 disagree between the two legs. */
    status = NtDebugActiveProcess(pi.hProcess, debugObject);
    ok(status == STATUS_ACCESS_DENIED, "second NtDebugActiveProcess -> %08lx",
       (unsigned long)status);

    /* --- detach -------------------------------------------------------- */
    status = NtRemoveProcessDebug(pi.hProcess, debugObject);
    ok(status == STATUS_SUCCESS, "NtRemoveProcessDebug -> %08lx", (unsigned long)status);
    ok(peb_byte(pi.hProcess, peb, PEB_BEING_DEBUGGED) == 0, "BeingDebugged set after detach");

    /* Detaching what is not attached is refused the same way (measured:
     * ACCESS_DENIED, not the documented STATUS_PORT_NOT_SET). */
    status = NtRemoveProcessDebug(pi.hProcess, debugObject);
    ok(status == STATUS_ACCESS_DENIED, "second NtRemoveProcessDebug -> %08lx",
       (unsigned long)status);

    /* --- the wrong-type refusals --------------------------------------- */
    status = NtDebugActiveProcess(pi.hProcess, pi.hThread);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "NtDebugActiveProcess(thread handle) -> %08lx",
       (unsigned long)status);
    status = NtDebugActiveProcess(debugObject, debugObject);
    ok(status == STATUS_OBJECT_TYPE_MISMATCH, "NtDebugActiveProcess(debug as process) -> %08lx",
       (unsigned long)status);

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(debugObject);
}
