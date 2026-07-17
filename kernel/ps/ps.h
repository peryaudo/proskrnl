/* kernel/ps/ps.h — the Ps department: processes and user threads (M4).
 *
 * EPROCESS internal layout is entirely ours (docs/05: "nobody reads it — no
 * drivers"); only the outside is strict, and at M4 the outside is small: a
 * process is an Ob object, waitable like NT's (signalled at termination,
 * never reset), owns a handle table and a user address space, and dies
 * through NtTerminateProcess or a contained user-mode fault. The byte-exact
 * TEB/PEB and NtCreateUserProcess arrive with M7; M4 processes run a flat
 * binary handed to the kernel as a Limine module (docs/02: "test client is
 * a flat binary, not yet a PE").
 */
#ifndef PROSKRNL_KERNEL_PS_PS_H
#define PROSKRNL_KERNEL_PS_PS_H

#include "abi/ntdef.h"
#include "abi/ntpsapi.h"
#include "kernel/ke/ke.h"
#include "kernel/ob/ob.h"
#include "kernel/mm/virtual.h"

typedef struct EPROCESS
{
    DISPATCHER_HEADER header; /* signalled at termination, never reset */
    MI_ADDRESS_SPACE addressSpace;
    OBP_HANDLE_TABLE handleTable;
    NTSTATUS exitStatus;
    PKTHREAD mainThread; /* M4: exactly one thread per user process */
    uint64_t entryRip;   /* flat-binary entry state, set before the */
    uint64_t entryRsp;   /* thread is readied */
    void *teb;
    const char *imageName; /* for dumps; storage owned by the caller */
} EPROCESS, *PEPROCESS;

extern OBJECT_TYPE PspProcessType;

/* The process kernel threads belong to. Its address space is the kernel
 * PML4 and its handle table is the one kmt/kernel Nt* callers use. */
extern PEPROCESS PsInitialSystemProcess;

/* Create the system process and freeze the kernel PML4's top level (process
 * page tables share it by copy — see arch/x86_64/mmu.h). Needs Ob; call
 * before the scheduler exists so every thread can carry a process. */
void PsInitializeProcessSubsystem(void);

/* Build a user process around a flat binary image: map it at the fixed
 * flat-binary base, give it a stack and a TEB (NT_TIB filled), and ready
 * its single thread. The caller owns the returned creator reference. */
NTSTATUS PspCreateUserProcess(const char *imageName, const void *image, uint64_t imageSize,
                              PEPROCESS *processOut);

/* Terminate the calling thread's process: close its handles, publish the
 * exit status, signal the process object, never return. The user-fault
 * containment path (panic.c) and NtTerminateProcess both land here. */
__attribute__((noreturn)) void PspExitCurrentProcess(NTSTATUS exitStatus);

/* Where the flat binary is mapped; its entry point is its first byte. */
#define PSP_IMAGE_BASE 0x400000ULL

/* Run one flat-binary boot module to completion from a kernel thread: create
 * the process, wait for it, and return its exit NTSTATUS. `imageName` is used
 * only for dumps. */
NTSTATUS PsRunBootModule(const char *imageName, const void *image, uint64_t imageSize,
                         NTSTATUS *exitStatusOut);

#endif /* PROSKRNL_KERNEL_PS_PS_H */
