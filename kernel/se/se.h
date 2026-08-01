/* kernel/se/se.h — the Se department: tokens and security (CUI-2, docs/02).
 *
 * One fixed identity, structurally real NT objects. The boundary this
 * reproduces is the COMBINATION of Wine's PE-invisible unix layer
 * (third_party/wine dlls/ntdll/unix/security.c: retlen pre-writes, the
 * fixed-length info table, the semi-stub classes) and wineserver
 * (server/token.c: the admin identity, adjust/duplicate semantics, the
 * access-check ACE walk; server/object.c: SD defaulting) — on proskrnl the
 * PE thunks syscall straight into the kernel, so both halves live here.
 * Pinned by tests/ntapi/sem_se/ (oracle-green first, Art. 5).
 *
 * Everything is always-allow at the Ob boundary (docs/05): tokens GATE
 * nothing yet — they exist so the dormant token reads in the already-baked
 * DLLs (kernelbase/security.c, ntdll/sec.c, advapi32) stop dying on
 * STATUS_NOT_IMPLEMENTED. Se enforces only the per-handle access masks Ob
 * already carries.
 */
#ifndef PROSKRNL_KERNEL_SE_SE_H
#define PROSKRNL_KERNEL_SE_SE_H

#include "abi/ntdef.h"
#include "abi/ntstatus.h"
#include "abi/ntseapi.h"
#include "kernel/ob/ob.h"

struct EPROCESS; /* kernel/ps/ps.h; Se and Ps include each other's edges */

/* --- the token object ----------------------------------------------------- */

/* One privilege a token holds (wineserver's struct privilege shape:
 * enabled + enabled-by-default bits; attributes are derived on read as
 * server/token.c luid_and_attr_from_privilege does). */
typedef struct SEP_PRIVILEGE
{
    LUID luid;
    BOOLEAN enabled;
    BOOLEAN enabledByDefault;
} SEP_PRIVILEGE, *PSEP_PRIVILEGE;

/* The token body: fixed header + ONE trailing variable blob in the same
 * pool block (user SID, group attribute array, packed group SIDs, the
 * privilege array, the default DACL). Single allocation keeps the G11
 * ownership audit trivial: the object block owns everything; the delete
 * procedure frees nothing extra. Offsets are relative to (BYTE *)(token+1).
 * Mutation only ever SHRINKS (SE_PRIVILEGE_REMOVED), never grows. */
typedef struct TOKEN
{
    LUID tokenId;            /* fresh from the one LUID authority */
    LUID modifiedId;         /* re-allocated on every adjust call */
    BOOLEAN primary;         /* TokenPrimary vs TokenImpersonation */
    LONG impersonationLevel; /* -1 for primary (server/token.c create_token) */
    ULONG sessionId;         /* 1 (server/process.h default_session_id) */
    LONG elevationType;      /* TOKEN_ELEVATION_TYPE */
    ULONG userSidLength;
    ULONG groupCount;
    ULONG privilegeCount;    /* live count; only shrinks */
    ULONG primaryGroupIndex; /* owner == primary group (create_token) */
    ULONG defaultDaclLength; /* 0 = no default DACL */
    ULONG userSidOffset;     /* trailing-blob offsets: */
    ULONG groupAttrsOffset;  /* ULONG[groupCount] */
    ULONG groupSidsOffset;   /* groupCount packed SIDs */
    ULONG groupSidsLength;
    ULONG privilegesOffset; /* SEP_PRIVILEGE[privilegeCount] */
    ULONG defaultDaclOffset;
    /* CUI-6: NtSetInformationToken(TokenDefaultDacl) can install a DACL that
     * does not fit the inline slot — the ONE documented exception to the
     * "only ever SHRINKS" rule above. A non-null override is a separate pool
     * allocation that takes precedence over the inline DACL (freed at token
     * delete; the ONE owning site, G11). */
    PACL defaultDaclOverride;
    ULONG defaultDaclOverrideLength;
} TOKEN, *PTOKEN;

extern OBJECT_TYPE SeTokenType;

/* The boot identity: minted once at init, byte-identical to wineserver's
 * token_create_admin so the sem_se differential can pin exact SID bytes.
 * Holds a permanent kernel reference; every process token is a duplicate. */
extern PTOKEN SeBootToken;

/* --- trailing-blob accessors ---------------------------------------------- */

static inline BYTE *SepTokenData(PTOKEN token)
{
    return (BYTE *)(token + 1);
}

static inline SID *SepTokenUserSid(PTOKEN token)
{
    return (SID *)(SepTokenData(token) + token->userSidOffset);
}

static inline ULONG *SepTokenGroupAttrs(PTOKEN token)
{
    return (ULONG *)(SepTokenData(token) + token->groupAttrsOffset);
}

static inline BYTE *SepTokenGroupSids(PTOKEN token)
{
    return SepTokenData(token) + token->groupSidsOffset;
}

static inline PSEP_PRIVILEGE SepTokenPrivileges(PTOKEN token)
{
    return (PSEP_PRIVILEGE)(SepTokenData(token) + token->privilegesOffset);
}

/* The effective default DACL: the CUI-6 override if one was installed,
 * else the inline slot (0 = none). The ONE reader of the token's default
 * DACL — the query and the secobj default-from-token merge both route
 * through it, so the override is honoured everywhere (G11). */
static inline ACL *SepTokenDefaultDacl(PTOKEN token)
{
    if (token->defaultDaclOverride != 0)
    {
        return token->defaultDaclOverride;
    }
    return token->defaultDaclLength != 0 ? (ACL *)(SepTokenData(token) + token->defaultDaclOffset)
                                         : 0;
}

/* The effective default DACL's length (override or inline). */
static inline ULONG SepTokenDefaultDaclLength(PTOKEN token)
{
    return token->defaultDaclOverride != 0 ? token->defaultDaclOverrideLength
                                           : token->defaultDaclLength;
}

/* On-wire SID size from its own header. */
static inline ULONG SepSidLength(const SID *sid)
{
    return (ULONG)(sizeof(SID) - sizeof(DWORD) + (ULONG)sid->SubAuthorityCount * sizeof(DWORD));
}

/* The i-th group SID (a walk; groupCount is at most the boot 8). */
SID *SepTokenGroupSid(PTOKEN token, ULONG index);

/* --- token.c --------------------------------------------------------------- */

/* Mint SeBootToken (the token_create_admin identity). Needs Ob + pool; call
 * between ObpInitializeObjectManager and PsInitializeProcessSubsystem. */
void SeInitializeSecuritySubsystem(void);

/* THE LUID authority (G11: one counter): token ids, modified ids and
 * NtAllocateLocallyUniqueId all draw from here. */
LUID SepAllocateLuid(void);

/* THE duplication engine (G11: one create path beyond the boot mint):
 * NtDuplicateToken and process-token inheritance both come through here.
 * Validates the impersonation-level rules (server/token.c token_duplicate);
 * on success the caller owns one reference to *newToken. */
NTSTATUS SepDuplicateToken(PTOKEN source, BOOLEAN primary, LONG impersonationLevel,
                           PTOKEN *newToken);

/* Ps integration (the one process-token mint/release site pair;
 * kernel/ps/process.c calls these from PspInitializeProcessCommon /
 * PspDeleteProcess). Assign duplicates the creator's token — or SeBootToken
 * when no thread context exists yet (the system process) — mirroring
 * wineserver's parentless-vs-child split (server/process.c). */
NTSTATUS SeAssignPrimaryToken(struct EPROCESS *process);
void SeDeassignPrimaryToken(struct EPROCESS *process);

/* The current thread's effective token (thread tokens do not exist in
 * CUI-2, so: the current process's token; SeBootToken without a thread). */
PTOKEN SeCurrentToken(void);

/* Membership test for the access-check walk and TokenElevation
 * (server/token.c token_sid_present): the user SID always matches; groups
 * must be SE_GROUP_ENABLED, and USE_FOR_DENY_ONLY ones only match deny. */
BOOLEAN SepTokenSidPresent(PTOKEN token, const SID *sid, BOOLEAN deny);

/* Privilege lookup + the check engine (server/token.c
 * token_find_privilege / token_check_privileges). usedAttrs may be 0. */
PSEP_PRIVILEGE SepTokenFindPrivilege(PTOKEN token, LUID luid);
BOOLEAN SepTokenCheckPrivileges(PTOKEN token, BOOLEAN allRequired,
                                const LUID_AND_ATTRIBUTES *required, ULONG count,
                                LUID_AND_ATTRIBUTES *used);

/* One-privilege caller check, NT's export shape ("SeSinglePrivilegeCheck
 * function (wdm.h)", MS Learn; not in the pinned Wine's ddk headers).
 * KernelMode always passes; else the effective token must hold the
 * privilege enabled. CUI-7: the Cm hive services' SeBackup/SeRestore gates
 * and the Ke time/shutdown gates all go through here. */
BOOLEAN SeSinglePrivilegeCheck(LUID privilegeValue, KPROCESSOR_MODE previousMode);

/* Resolve a token handle (magic pseudo-handles included, via
 * ObReferenceObjectByHandle). Caller dereferences. */
NTSTATUS SepReferenceTokenByHandle(HANDLE handle, ACCESS_MASK desiredAccess, PTOKEN *token,
                                   POBJECT_HANDLE_INFORMATION handleInformation);

/* --- sd.c: security-descriptor plumbing ------------------------------------ */

/* The stored form on OBJECT_HEADER.securityDescriptor and the capture
 * output: wineserver's internal shape (server_protocol.h struct
 * security_descriptor) — a header + owner/group/sacl/dacl parts packed in
 * that order. control never carries SE_SELF_RELATIVE. */
typedef struct SEP_SECURITY_DESCRIPTOR
{
    USHORT control;
    ULONG ownerLength;
    ULONG groupLength;
    ULONG saclLength;
    ULONG daclLength;
} SEP_SECURITY_DESCRIPTOR, *PSEP_SECURITY_DESCRIPTOR;

static inline BYTE *SepSdData(PSEP_SECURITY_DESCRIPTOR sd)
{
    return (BYTE *)(sd + 1);
}

static inline ULONG SepSdTotalLength(PSEP_SECURITY_DESCRIPTOR sd)
{
    return (ULONG)sizeof(*sd) + sd->ownerLength + sd->groupLength + sd->saclLength + sd->daclLength;
}

/* Capture a caller's SECURITY_DESCRIPTOR (absolute or self-relative — the
 * SE_SELF_RELATIVE control bit decides; on the oracle ntdll's marshalling
 * normalizes, on proskrnl the kernel must) into a pooled SEP blob the
 * caller frees. Validates SIDs and walks ACLs (bounds per wineserver's
 * sd_is_valid / acl_is_valid); malformed input is STATUS_ACCESS_VIOLATION,
 * as the server answers an invalid inline SD. */
NTSTATUS SepCaptureSecurityDescriptor(PSECURITY_DESCRIPTOR userSd,
                                      PSEP_SECURITY_DESCRIPTOR *captured);

/* CUI-6: capture an OBJECT_ATTRIBUTES security descriptor onto an object at
 * create time (`objectHeader` is a POBJECT_HEADER; the stored blob is freed
 * on object delete — the ONE create-time SD site, G11). A partial SD is
 * stored as given; token-defaulting of missing parts is NtSetSecurityObject's
 * job (no baked create passes a partial SD). No-op for a NULL descriptor. */
NTSTATUS SeCaptureObjectSecurity(PVOID objectHeader, PSECURITY_DESCRIPTOR userSd);

/* CUI-6: the Ob create/open access authority (access.c). */
NTSTATUS SeCheckObjectAccess(POBJECT_TYPE type, PVOID securityDescriptor, ACCESS_MASK desiredAccess,
                             ACCESS_MASK mappedAccess, ACCESS_MASK *grantedAccess);

/* sd.c internals shared with access.c/secobj.c: validated-part helpers. */
BOOLEAN SepIsValidSid(const SID *sid, ULONG availableLength);
BOOLEAN SepIsValidAcl(const ACL *acl, ULONG availableLength);

#endif /* PROSKRNL_KERNEL_SE_SE_H */
