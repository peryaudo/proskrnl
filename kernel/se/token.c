/* kernel/se/token.c — the token object, the fixed boot identity, and the
 * token syscall surface (CUI-2, docs/02).
 *
 * The identity minted here is byte-identical to wineserver's
 * token_create_admin (third_party/wine server/token.c) so the sem_se
 * differential suite can pin exact SID bytes on both sides: user
 * S-1-5-21-0-0-0-1000, owner/primary group Domain Users, the 8-group /
 * 21-privilege admin set, the 2-ACE default DACL, session 1,
 * TokenElevationTypeLimited. Composition (which groups, which order, which
 * enabled bits) is transcribed from server/token.c; every numeric ingredient
 * (authorities, RIDs, SE_* attribute bits, privilege LUID values) comes from
 * the generated abi/ntseapi.h (G4).
 *
 * Query semantics mirror the ORACLE COMBINATION (see kernel/se/se.h): the
 * unix layer's retlen pre-writes and fixed-length table
 * (dlls/ntdll/unix/security.c NtQueryInformationToken) plus wineserver's
 * per-request handlers. Where the two disagree with real-NT folklore, the
 * oracle wins (Art. 6).
 */
#include "kernel/se/se.h"
#include "kernel/ps/ps.h"
#include "kernel/ke/ke.h"
#include "kernel/mm/pool.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

/* --- the type ------------------------------------------------------------- */

/* CUI-6: free the side-allocated default-DACL override (the token's inline
 * blob is part of the object block and needs no free). */
static void SepDeleteToken(PVOID body)
{
    PTOKEN token = body;
    if (token->defaultDaclOverride != 0)
    {
        MiFreePool(token->defaultDaclOverride);
    }
}

OBJECT_TYPE SeTokenType = {
    .name = "Token",
    .validAccess = TOKEN_ALL_ACCESS | SYNCHRONIZE,
    .waitable = FALSE,
    .deleteProcedure = SepDeleteToken,
    /* The real NT generic mapping, composed exactly as wineserver's
     * token_type (third_party/wine server/token.c) composes it. */
    .genericRead = STANDARD_RIGHTS_READ | TOKEN_QUERY_SOURCE | TOKEN_QUERY | TOKEN_DUPLICATE,
    .genericWrite = STANDARD_RIGHTS_WRITE | TOKEN_ADJUST_SESSIONID | TOKEN_ADJUST_DEFAULT |
                    TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_PRIVILEGES,
    .genericExecute = STANDARD_RIGHTS_EXECUTE | TOKEN_IMPERSONATE | TOKEN_ASSIGN_PRIMARY,
    .genericAll = TOKEN_ALL_ACCESS,
};

PTOKEN SeBootToken;

/* --- THE LUID authority (G11: one counter) --------------------------------
 * Seeded and advanced exactly as wineserver's prev_luid_value
 * (server/token.c: `{ 1000, 0 }`, pre-incremented low part, no carry). */
static LUID SepPreviousLuid = {1000, 0};

LUID SepAllocateLuid(void)
{
    SepPreviousLuid.LowPart++;
    return SepPreviousLuid;
}

/* --- the boot identity's SIDs ---------------------------------------------
 * Transcribed from third_party/wine server/token.c (world_sid, local_sid,
 * interactive_sid, authenticated_user_sid, local_user_sid, domain_users_sid,
 * builtin_admins_sid, builtin_users_sid, logon_sid, local_system_sid,
 * high_label_sid). The 21-0-0-0-{1000,513} spellings are wineserver's
 * literal local_user_sid / domain_users_sid values (its
 * security_unix_uid_to_sid maps the server's own uid there
 * unconditionally). */
typedef struct SEP_SID_BUFFER
{
    BYTE revision;
    BYTE subAuthorityCount;
    SID_IDENTIFIER_AUTHORITY identifierAuthority;
    DWORD subAuthority[SID_MAX_SUB_AUTHORITIES];
} SEP_SID_BUFFER;

#define SEP_SID(name, count, auth, ...)                                                            \
    static const SEP_SID_BUFFER name = {SID_REVISION, count, {auth}, {__VA_ARGS__}}

SEP_SID(SepWorldSid, 1, SECURITY_WORLD_SID_AUTHORITY, SECURITY_WORLD_RID);
SEP_SID(SepLocalSid, 1, SECURITY_LOCAL_SID_AUTHORITY, SECURITY_LOCAL_RID);
SEP_SID(SepInteractiveSid, 1, SECURITY_NT_AUTHORITY, SECURITY_INTERACTIVE_RID);
SEP_SID(SepAuthenticatedUserSid, 1, SECURITY_NT_AUTHORITY, SECURITY_AUTHENTICATED_USER_RID);
SEP_SID(SepLocalSystemSid, 1, SECURITY_NT_AUTHORITY, SECURITY_LOCAL_SYSTEM_RID);
SEP_SID(SepLocalUserSid, 5, SECURITY_NT_AUTHORITY, SECURITY_NT_NON_UNIQUE, 0, 0, 0, 1000);
SEP_SID(SepDomainUsersSid, 5, SECURITY_NT_AUTHORITY, SECURITY_NT_NON_UNIQUE, 0, 0, 0,
        DOMAIN_GROUP_RID_USERS);
SEP_SID(SepBuiltinAdminsSid, 2, SECURITY_NT_AUTHORITY, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS);
SEP_SID(SepBuiltinUsersSid, 2, SECURITY_NT_AUTHORITY, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_USERS);
SEP_SID(SepLogonSid, 3, SECURITY_NT_AUTHORITY, SECURITY_LOGON_IDS_RID, 0, 0);
SEP_SID(SepHighLabelSid, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_HIGH_RID);
/* CUI-6: S-1-5-7, the ANONYMOUS LOGON user NtImpersonateAnonymousToken mints. */
SEP_SID(SepAnonymousLogonSid, 1, SECURITY_NT_AUTHORITY, SECURITY_ANONYMOUS_LOGON_RID);

static const SID *SepSidOf(const SEP_SID_BUFFER *buffer)
{
    return (const SID *)buffer;
}

/* --- accessors ------------------------------------------------------------- */

SID *SepTokenGroupSid(PTOKEN token, ULONG index)
{
    ASSERT(index < token->groupCount);
    BYTE *cursor = SepTokenGroupSids(token);
    for (ULONG i = 0; i < index; i++)
    {
        cursor += SepSidLength((SID *)cursor);
    }
    return (SID *)cursor;
}

BOOLEAN SepTokenSidPresent(PTOKEN token, const SID *sid, BOOLEAN deny)
{
    ULONG length = SepSidLength(sid);
    SID *user = SepTokenUserSid(token);
    if (SepSidLength(user) == length && memcmp(user, sid, length) == 0)
    {
        return TRUE;
    }
    ULONG *attrs = SepTokenGroupAttrs(token);
    BYTE *cursor = SepTokenGroupSids(token);
    for (ULONG i = 0; i < token->groupCount; i++)
    {
        SID *group = (SID *)cursor;
        cursor += SepSidLength(group);
        if ((attrs[i] & SE_GROUP_ENABLED) == 0)
        {
            continue;
        }
        if (!deny && (attrs[i] & SE_GROUP_USE_FOR_DENY_ONLY) != 0)
        {
            continue;
        }
        if (SepSidLength(group) == length && memcmp(group, sid, length) == 0)
        {
            return TRUE;
        }
    }
    return FALSE;
}

PSEP_PRIVILEGE SepTokenFindPrivilege(PTOKEN token, LUID luid)
{
    PSEP_PRIVILEGE privileges = SepTokenPrivileges(token);
    for (ULONG i = 0; i < token->privilegeCount; i++)
    {
        if (privileges[i].luid.LowPart == luid.LowPart &&
            privileges[i].luid.HighPart == luid.HighPart)
        {
            return &privileges[i];
        }
    }
    return 0;
}

BOOLEAN SepTokenCheckPrivileges(PTOKEN token, BOOLEAN allRequired,
                                const LUID_AND_ATTRIBUTES *required, ULONG count,
                                LUID_AND_ATTRIBUTES *used)
{
    ULONG enabledCount = 0;
    for (ULONG i = 0; i < count; i++)
    {
        PSEP_PRIVILEGE privilege = SepTokenFindPrivilege(token, required[i].Luid);
        if (used != 0)
        {
            used[i] = required[i];
        }
        if (privilege != 0 && privilege->enabled)
        {
            enabledCount++;
            if (used != 0)
            {
                used[i].Attributes |= SE_PRIVILEGE_USED_FOR_ACCESS;
            }
        }
    }
    return allRequired ? (enabledCount == count) : (enabledCount > 0);
}

BOOLEAN SeSinglePrivilegeCheck(LUID privilegeValue, KPROCESSOR_MODE previousMode)
{
    /* NT's real export shape ("SeSinglePrivilegeCheck function (wdm.h)",
     * MS Learn — absent from the pinned Wine's ddk headers): a KernelMode
     * caller always passes; otherwise the caller's EFFECTIVE token must
     * hold the privilege enabled (wineserver thread_single_check_privilege,
     * server/token.c: current->token ?: process->token). One check engine
     * (Art. 11): the same SepTokenCheckPrivileges walk NtPrivilegeCheck
     * uses. */
    if (previousMode == KernelMode)
    {
        return TRUE;
    }
    LUID_AND_ATTRIBUTES required;
    required.Luid = privilegeValue;
    required.Attributes = 0;
    return SepTokenCheckPrivileges(SeCurrentToken(), TRUE, &required, 1, 0);
}

/* --- THE create engine (G11) ----------------------------------------------
 * Everything is one pool block: TOKEN + user SID + group attrs + packed
 * group SIDs + privilege array + default DACL. Offsets 8-aligned. */
static ULONG SepAlign8(ULONG value)
{
    return (value + 7) & ~7U;
}

static NTSTATUS SepCreateToken(BOOLEAN primary, LONG impersonationLevel, ULONG sessionId,
                               LONG elevationType, const SID *userSid, const ULONG *groupAttrs,
                               const BYTE *groupSids, ULONG groupSidsLength, ULONG groupCount,
                               const SEP_PRIVILEGE *privileges, ULONG privilegeCount,
                               const ACL *defaultDacl, ULONG defaultDaclLength,
                               const LUID *modifiedId, ULONG primaryGroupIndex, PTOKEN *out)
{
    ULONG userSidLength = SepSidLength(userSid);
    ULONG userSidOffset = 0;
    ULONG groupAttrsOffset = SepAlign8(userSidOffset + userSidLength);
    ULONG groupSidsOffset = SepAlign8(groupAttrsOffset + groupCount * (ULONG)sizeof(ULONG));
    ULONG privilegesOffset = SepAlign8(groupSidsOffset + groupSidsLength);
    ULONG defaultDaclOffset =
        SepAlign8(privilegesOffset + privilegeCount * (ULONG)sizeof(SEP_PRIVILEGE));
    ULONG totalLength = defaultDaclOffset + defaultDaclLength;

    PVOID body;
    NTSTATUS status = ObpAllocateObject(&SeTokenType, sizeof(TOKEN) + totalLength, &body);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PTOKEN token = body;
    token->tokenId = SepAllocateLuid();
    token->modifiedId = modifiedId != 0 ? *modifiedId : SepAllocateLuid();
    token->primary = primary;
    /* primary tokens don't have impersonation levels (server/token.c
     * create_token) */
    token->impersonationLevel = primary ? -1 : impersonationLevel;
    token->sessionId = sessionId;
    token->elevationType = elevationType;
    token->userSidLength = userSidLength;
    token->groupCount = groupCount;
    token->privilegeCount = privilegeCount;
    token->primaryGroupIndex = primaryGroupIndex;
    token->defaultDaclLength = defaultDaclLength;
    token->userSidOffset = userSidOffset;
    token->groupAttrsOffset = groupAttrsOffset;
    token->groupSidsOffset = groupSidsOffset;
    token->groupSidsLength = groupSidsLength;
    token->privilegesOffset = privilegesOffset;
    token->defaultDaclOffset = defaultDaclOffset;
    token->defaultDaclOverride = 0; /* CUI-6: no override until a set installs one */
    token->defaultDaclOverrideLength = 0;

    BYTE *data = SepTokenData(token);
    memcpy(data + userSidOffset, userSid, userSidLength);
    memcpy(data + groupAttrsOffset, groupAttrs, groupCount * sizeof(ULONG));
    memcpy(data + groupSidsOffset, groupSids, groupSidsLength);
    memcpy(data + privilegesOffset, privileges, privilegeCount * sizeof(SEP_PRIVILEGE));
    if (defaultDaclLength != 0)
    {
        memcpy(data + defaultDaclOffset, defaultDacl, defaultDaclLength);
    }
    *out = token;
    return STATUS_SUCCESS;
}

/* --- THE duplication engine (G11) ------------------------------------------ */

NTSTATUS SepDuplicateToken(PTOKEN source, BOOLEAN primary, LONG impersonationLevel,
                           PTOKEN *newToken)
{
    /* Level rules per server/token.c token_duplicate: an impersonation
     * duplicate needs a level in range, and may never RAISE the level of an
     * impersonation source. */
    if (!primary &&
        (impersonationLevel < SecurityAnonymous || impersonationLevel > SecurityDelegation ||
         (!source->primary && impersonationLevel > source->impersonationLevel)))
    {
        return STATUS_BAD_IMPERSONATION_LEVEL;
    }
    /* The modified id is COPIED for a primary duplicate or a same-level
     * impersonation one, fresh otherwise (token_duplicate). */
    const LUID *modifiedId =
        (primary || impersonationLevel == source->impersonationLevel) ? &source->modifiedId : 0;

    return SepCreateToken(primary, impersonationLevel, source->sessionId, source->elevationType,
                          SepTokenUserSid(source), SepTokenGroupAttrs(source),
                          SepTokenGroupSids(source), source->groupSidsLength, source->groupCount,
                          SepTokenPrivileges(source), source->privilegeCount,
                          SepTokenDefaultDacl(source), SepTokenDefaultDaclLength(source),
                          modifiedId, source->primaryGroupIndex, newToken);
}

/* CUI-6: THE filter engine (wineserver filter_token -> token_duplicate with
 * disable/delete lists), extending — not forking — SepCreateToken (G11). A
 * disabled group survives as SE_GROUP_USE_FOR_DENY_ONLY (server/token.c
 * token_duplicate), a deleted privilege is dropped, and the type/level/
 * modified-id are the source's (same-type same-level duplicate). */
static NTSTATUS SepFilterToken(PTOKEN source, const BYTE *disableSids, ULONG disableCount,
                               const LUID *deleteLuids, ULONG deleteCount, PTOKEN *out)
{
    /* Modified group attributes: same count, deny-only for disabled SIDs. */
    ULONG *attrs = MiAllocatePool(source->groupCount * sizeof(ULONG) + 1);
    if (attrs == 0)
    {
        return STATUS_NO_MEMORY;
    }
    const ULONG *srcAttrs = SepTokenGroupAttrs(source);
    const BYTE *cursor = SepTokenGroupSids(source);
    for (ULONG i = 0; i < source->groupCount; i++)
    {
        const SID *sid = (const SID *)cursor;
        ULONG sidLen = SepSidLength(sid);
        ULONG a = srcAttrs[i];
        const BYTE *dcursor = disableSids;
        for (ULONG d = 0; d < disableCount; d++)
        {
            const SID *dsid = (const SID *)dcursor;
            ULONG dlen = SepSidLength(dsid);
            if (dlen == sidLen && memcmp(dsid, sid, sidLen) == 0)
            {
                a &= ~(ULONG)(SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT);
                a |= SE_GROUP_USE_FOR_DENY_ONLY;
                break;
            }
            dcursor += dlen;
        }
        attrs[i] = a;
        cursor += sidLen;
    }

    /* Filtered privileges: drop those named in the delete list. */
    ULONG maxPriv = source->privilegeCount;
    PSEP_PRIVILEGE privs = MiAllocatePool(maxPriv * sizeof(SEP_PRIVILEGE) + 1);
    if (privs == 0)
    {
        MiFreePool(attrs);
        return STATUS_NO_MEMORY;
    }
    const SEP_PRIVILEGE *srcPrivs = SepTokenPrivileges(source);
    ULONG privCount = 0;
    for (ULONG i = 0; i < source->privilegeCount; i++)
    {
        BOOLEAN deleted = FALSE;
        for (ULONG d = 0; d < deleteCount; d++)
        {
            if (deleteLuids[d].LowPart == srcPrivs[i].luid.LowPart &&
                deleteLuids[d].HighPart == srcPrivs[i].luid.HighPart)
            {
                deleted = TRUE;
                break;
            }
        }
        if (!deleted)
        {
            privs[privCount++] = srcPrivs[i];
        }
    }

    /* Same type/level -> the modified id is copied (token_duplicate rule). */
    NTSTATUS status = SepCreateToken(
        source->primary, source->impersonationLevel, source->sessionId, source->elevationType,
        SepTokenUserSid(source), attrs, SepTokenGroupSids(source), source->groupSidsLength,
        source->groupCount, privs, privCount, SepTokenDefaultDacl(source),
        SepTokenDefaultDaclLength(source), &source->modifiedId, source->primaryGroupIndex, out);
    MiFreePool(privs);
    MiFreePool(attrs);
    return status;
}

/* --- the boot mint ---------------------------------------------------------- */

void SeInitializeSecuritySubsystem(void)
{
    /* The 8 groups, in server/token.c token_create_admin's admin_groups[]
     * order and with its exact attribute sets. Index 4 (Domain Users) is
     * the primary group AND the owner (create_token: primary_group == 4). */
    static const ULONG mandatory =
        SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
    const SID *groups[8] = {
        SepSidOf(&SepWorldSid),        SepSidOf(&SepLocalSid),
        SepSidOf(&SepInteractiveSid),  SepSidOf(&SepAuthenticatedUserSid),
        SepSidOf(&SepDomainUsersSid),  SepSidOf(&SepBuiltinAdminsSid),
        SepSidOf(&SepBuiltinUsersSid), SepSidOf(&SepLogonSid),
    };
    ULONG attrs[8] = {
        mandatory,
        mandatory,
        mandatory,
        mandatory,
        mandatory | SE_GROUP_OWNER,
        mandatory | SE_GROUP_OWNER,
        mandatory,
        mandatory | SE_GROUP_LOGON_ID,
    };
    BYTE packedSids[8 * sizeof(SEP_SID_BUFFER)];
    ULONG packedLength = 0;
    for (ULONG i = 0; i < 8; i++)
    {
        ULONG length = SepSidLength(groups[i]);
        memcpy(packedSids + packedLength, groups[i], length);
        packedLength += length;
    }

    /* The 21 privileges, in admin_privs[] order; enabled-by-default:
     * SeChangeNotify, SeLoadDriver, SeImpersonate, SeCreateGlobal
     * (server/token.c token_create_admin). LUID values from winternl.h's
     * SE_*_PRIVILEGE via abi/ (wineserver spells the same numbers as its
     * own const luids, server/token.c top). */
    static const struct
    {
        DWORD luidLow;
        BOOLEAN enabled;
    } adminPrivileges[21] = {
        {SE_CHANGE_NOTIFY_PRIVILEGE, TRUE},
        {SE_TCB_PRIVILEGE, FALSE},
        {SE_SECURITY_PRIVILEGE, FALSE},
        {SE_BACKUP_PRIVILEGE, FALSE},
        {SE_RESTORE_PRIVILEGE, FALSE},
        {SE_SYSTEMTIME_PRIVILEGE, FALSE},
        {SE_SHUTDOWN_PRIVILEGE, FALSE},
        {SE_REMOTE_SHUTDOWN_PRIVILEGE, FALSE},
        {SE_TAKE_OWNERSHIP_PRIVILEGE, FALSE},
        {SE_DEBUG_PRIVILEGE, FALSE},
        {SE_SYSTEM_ENVIRONMENT_PRIVILEGE, FALSE},
        {SE_SYSTEM_PROFILE_PRIVILEGE, FALSE},
        {SE_PROF_SINGLE_PROCESS_PRIVILEGE, FALSE},
        {SE_INC_BASE_PRIORITY_PRIVILEGE, FALSE},
        {SE_LOAD_DRIVER_PRIVILEGE, TRUE},
        {SE_CREATE_PAGEFILE_PRIVILEGE, FALSE},
        {SE_INCREASE_QUOTA_PRIVILEGE, FALSE},
        {SE_UNDOCK_PRIVILEGE, FALSE},
        {SE_MANAGE_VOLUME_PRIVILEGE, FALSE},
        {SE_IMPERSONATE_PRIVILEGE, TRUE},
        {SE_CREATE_GLOBAL_PRIVILEGE, TRUE},
    };
    SEP_PRIVILEGE privileges[21];
    for (ULONG i = 0; i < 21; i++)
    {
        privileges[i].luid.LowPart = adminPrivileges[i].luidLow;
        privileges[i].luid.HighPart = 0;
        privileges[i].enabled = adminPrivileges[i].enabled;
        privileges[i].enabledByDefault = adminPrivileges[i].enabled;
    }

    /* The default DACL: SYSTEM:GENERIC_ALL + DomainUsers:GENERIC_ALL
     * (server/token.c create_default_dacl, called with domain_users_sid). */
    BYTE dacl[sizeof(ACL) + 2 * (sizeof(ACE_HEADER) + sizeof(ACCESS_MASK)) +
              sizeof(SEP_SID_BUFFER) * 2];
    ULONG daclLength = sizeof(ACL);
    const SID *aceSids[2] = {SepSidOf(&SepLocalSystemSid), SepSidOf(&SepDomainUsersSid)};
    for (ULONG i = 0; i < 2; i++)
    {
        ACE_HEADER *ace = (ACE_HEADER *)(dacl + daclLength);
        ULONG sidLength = SepSidLength(aceSids[i]);
        ace->AceType = ACCESS_ALLOWED_ACE_TYPE;
        ace->AceFlags = 0;
        ace->AceSize = (WORD)(sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) + sidLength);
        *(ACCESS_MASK *)(dacl + daclLength + sizeof(ACE_HEADER)) = GENERIC_ALL;
        memcpy(dacl + daclLength + sizeof(ACE_HEADER) + sizeof(ACCESS_MASK), aceSids[i], sidLength);
        daclLength += ace->AceSize;
    }
    ACL *daclHeader = (ACL *)dacl;
    daclHeader->AclRevision = ACL_REVISION;
    daclHeader->Sbz1 = 0;
    daclHeader->AclSize = (WORD)daclLength;
    daclHeader->AceCount = 2;
    daclHeader->Sbz2 = 0;

    /* The boot line: a primary admin token, TokenElevationTypeLimited,
     * session 1 (server/process.c: parentless -> token_create_admin(TRUE,
     * -1, TokenElevationTypeLimited, default_session_id);
     * server/process.h: default_session_id = 1). */
    PTOKEN token;
    NTSTATUS status = SepCreateToken(TRUE, -1, 1, TokenElevationTypeLimited,
                                     SepSidOf(&SepLocalUserSid), attrs, packedSids, packedLength, 8,
                                     privileges, 21, (const ACL *)dacl, daclLength, 0, 4, &token);
    if (!NT_SUCCESS(status))
    {
        KiPanic("SeInitializeSecuritySubsystem: cannot mint the boot token");
    }
    /* Permanent kernel reference (the creator's); never dropped. */
    SeBootToken = token;
}

/* --- Ps integration (the one process-token mint site pair) ------------------ */

PTOKEN SeCurrentToken(void)
{
    PKTHREAD thread = KeGetCurrentThread();
    if (thread == 0 || thread->process == 0 || thread->process->token == 0)
    {
        return SeBootToken;
    }
    /* CUI-6: the thread's impersonation token wins when one is attached
     * (server/token.c check_object_access: current->token ?: process->token),
     * else the process's primary token. */
    PVOID impersonation = PsCurrentThreadImpersonationToken();
    if (impersonation != 0)
    {
        return (PTOKEN)impersonation;
    }
    return (PTOKEN)thread->process->token;
}

NTSTATUS SeAssignPrimaryToken(struct EPROCESS *process)
{
    /* A child's token is a primary DUPLICATE of the creator's, never shared
     * (server/process.c: `token_duplicate( parent->token, TRUE, 0, ... )`),
     * so adjustments in one process are invisible in another and every
     * process observes a distinct TokenId. Without thread context (the
     * system process minting itself at boot) the parent is the boot line. */
    PTOKEN token;
    NTSTATUS status = SepDuplicateToken(SeCurrentToken(), TRUE, 0, &token);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    process->token = (struct TOKEN *)token;
    return STATUS_SUCCESS;
}

void SeDeassignPrimaryToken(struct EPROCESS *process)
{
    /* Ownership audit (G11): EPROCESS holds exactly one reference from
     * SeAssignPrimaryToken; token HANDLES hold their own via Ob. Dropping
     * ours here may or may not delete the object — open handles keep it. */
    if (process->token != 0)
    {
        ObDereferenceObject(process->token);
        process->token = 0;
    }
}

NTSTATUS SepReferenceTokenByHandle(HANDLE handle, ACCESS_MASK desiredAccess, PTOKEN *token,
                                   POBJECT_HANDLE_INFORMATION handleInformation)
{
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(handle, desiredAccess, &SeTokenType,
                                                ExGetPreviousMode(), &body, handleInformation);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *token = body;
    return STATUS_SUCCESS;
}

/* --- opening tokens --------------------------------------------------------- */

/* Pre-zero the caller's out-handle: the oracle's unix layer writes
 * `*handle = 0` before the server call (dlls/ntdll/unix/security.c
 * NtOpenProcessTokenEx / NtOpenThreadTokenEx); on proskrnl only the kernel
 * can keep that observable. */
static NTSTATUS SepPreZeroHandle(PHANDLE handleOut)
{
    NTSTATUS status = KiProbeForWrite(handleOut, sizeof(*handleOut), sizeof(*handleOut));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *handleOut = 0;
    return STATUS_SUCCESS;
}

NTSTATUS NtOpenProcessTokenEx(HANDLE processHandle, DWORD desiredAccess, DWORD handleAttributes,
                              HANDLE *tokenHandle)
{
    NTSTATUS status = SepPreZeroHandle(tokenHandle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* The process handle is resolved with NO required access (wineserver
     * open_token: get_process_from_handle(handle, 0)). */
    PEPROCESS process;
    BOOLEAN referenced = FALSE;
    if (processHandle == NtCurrentProcess())
    {
        process = KeGetCurrentThread()->process;
    }
    else
    {
        PVOID body;
        status = ObReferenceObjectByHandle(processHandle, 0, &PspProcessType, ExGetPreviousMode(),
                                           &body, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        process = body;
        referenced = TRUE;
    }

    /* The handle references the process's token OBJECT itself, never a
     * copy: adjustments through one open are visible through another
     * (sem_se/se_open pins the shared object). */
    PTOKEN token = (PTOKEN)process->token;
    if (token == 0)
    {
        status = STATUS_NO_TOKEN;
    }
    else
    {
        ACCESS_MASK granted = ObpMapDesiredAccess(&SeTokenType, desiredAccess);
        status = ObpCreateHandle(token, granted, handleAttributes, tokenHandle);
    }
    if (referenced)
    {
        ObDereferenceObject(process);
    }
    return status;
}

NTSTATUS NtOpenProcessToken(HANDLE processHandle, DWORD desiredAccess, HANDLE *tokenHandle)
{
    return NtOpenProcessTokenEx(processHandle, desiredAccess, 0, tokenHandle);
}

NTSTATUS NtOpenThreadTokenEx(HANDLE threadHandle, DWORD desiredAccess, BOOLEAN openAsSelf,
                             DWORD handleAttributes, HANDLE *tokenHandle)
{
    (void)openAsSelf;
    NTSTATUS status = SepPreZeroHandle(tokenHandle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* CUI-6: resolve the thread's impersonation token, if any (wineserver
     * open_token OPEN_TOKEN_THREAD; sem_se/se_impersonate). No token ->
     * STATUS_NO_TOKEN; an anonymous-level one -> STATUS_CANT_OPEN_ANONYMOUS.
     * The handle is resolved with no required access (get_thread_from_handle
     * ..., 0). */
    PETHREAD thread;
    if (threadHandle == NtCurrentThread())
    {
        thread = KeGetCurrentThread()->threadObject;
    }
    else
    {
        PVOID body;
        status = ObReferenceObjectByHandle(threadHandle, 0, &PspThreadType, ExGetPreviousMode(),
                                           &body, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        thread = body;
    }

    PTOKEN token = thread != 0 ? (PTOKEN)thread->impersonationToken : 0;
    if (token == 0)
    {
        status = STATUS_NO_TOKEN;
    }
    else if (!token->primary && token->impersonationLevel <= SecurityAnonymous)
    {
        status = STATUS_CANT_OPEN_ANONYMOUS;
    }
    else
    {
        ACCESS_MASK granted = ObpMapDesiredAccess(&SeTokenType, desiredAccess);
        status = ObpCreateHandle(token, granted, handleAttributes, tokenHandle);
    }

    if (threadHandle != NtCurrentThread() && thread != 0)
    {
        ObDereferenceObject(thread);
    }
    return status;
}

NTSTATUS NtOpenThreadToken(HANDLE threadHandle, DWORD desiredAccess, BOOLEAN openAsSelf,
                           HANDLE *tokenHandle)
{
    return NtOpenThreadTokenEx(threadHandle, desiredAccess, openAsSelf, 0, tokenHandle);
}

/* --- NtAllocateLocallyUniqueId ---------------------------------------------- */

NTSTATUS NtAllocateLocallyUniqueId(LUID *luid)
{
    /* The explicit NULL check precedes the probe (unix NtAllocateLocallyUniqueId). */
    if (luid == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    NTSTATUS status = KiProbeForWrite(luid, sizeof(*luid), sizeof(ULONG));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *luid = SepAllocateLuid();
    return STATUS_SUCCESS;
}

/* --- NtQueryInformationToken ------------------------------------------------ */

/* The unix layer's fixed-length table (dlls/ntdll/unix/security.c info_len):
 * decides the retlen PRE-WRITE and the up-front BUFFER_TOO_SMALL gate for
 * fixed-size classes, before any real work. Unlisted classes are 0. (The
 * oracle indexes this table out of bounds for classes 41..50 — a read of
 * arbitrary neighbours; those classes are unpinnable and get 0 here.) */
static ULONG SepTokenInfoLength(TOKEN_INFORMATION_CLASS infoClass)
{
    switch (infoClass)
    {
    case TokenSource:
        return sizeof(TOKEN_SOURCE);
    case TokenType:
        return sizeof(TOKEN_TYPE);
    case TokenImpersonationLevel:
        return sizeof(SECURITY_IMPERSONATION_LEVEL);
    case TokenStatistics:
        return sizeof(TOKEN_STATISTICS);
    case TokenSessionId:
        return sizeof(DWORD);
    case TokenElevationType:
        return sizeof(TOKEN_ELEVATION_TYPE);
    case TokenLinkedToken:
        return sizeof(TOKEN_LINKED_TOKEN);
    case TokenElevation:
        return sizeof(TOKEN_ELEVATION);
    case TokenVirtualizationEnabled:
        return sizeof(DWORD);
    case TokenIntegrityLevel:
        /* sizeof(SID) is the 1-subauthority SID — mirror the oracle's
         * arithmetic, don't re-derive (info_len comment in the source). */
        return sizeof(TOKEN_MANDATORY_LABEL) + sizeof(SID);
    case TokenUIAccess:
        return sizeof(DWORD);
    case TokenIsAppContainer:
        return sizeof(DWORD);
    case TokenAppContainerSid:
        return sizeof(TOKEN_APPCONTAINER_INFORMATION) + sizeof(SID);
    default:
        return 0;
    }
}

/* Copy a built reply to the user buffer (single probe + copy). */
static NTSTATUS SepCopyToUser(PVOID userBuffer, const void *reply, ULONG length)
{
    NTSTATUS status = KiProbeForWrite(userBuffer, length, sizeof(ULONG));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    memcpy(userBuffer, reply, length);
    return STATUS_SUCCESS;
}

static NTSTATUS SepWriteReturnLength(PULONG returnLength, ULONG value)
{
    if (returnLength == 0)
    {
        return STATUS_SUCCESS;
    }
    NTSTATUS status = KiProbeForWrite(returnLength, sizeof(*returnLength), sizeof(ULONG));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *returnLength = value;
    return STATUS_SUCCESS;
}

/* The largest reply the fixed identity can produce (TokenGroups: 264). */
#define SEP_QUERY_REPLY_MAX 512

NTSTATUS NtQueryInformationToken(HANDLE tokenHandle, TOKEN_INFORMATION_CLASS infoClass,
                                 PVOID buffer, ULONG length, PULONG returnLength)
{
    /* Zeroed once, for every class. The structures assembled in here are
     * pinned by abi/ntseapi.h and therefore have PADDING -- 4 bytes in
     * TOKEN_USER, 4 + 4 per group in TOKEN_GROUPS (36 with the boot token's
     * eight groups), 4 in TOKEN_MANDATORY_LABEL, which does not even need a
     * valid handle -- and every one of those bytes was copied out to ring 3
     * verbatim from an uninitialized kernel stack buffer: a repeatable
     * kernel-stack disclosure oracle (docs/review-2026-07 §10).
     * TokenStatistics already memset for exactly this reason; doing it once
     * here is what makes the property hold for the classes nobody thought
     * about, including ones added later. */
    BYTE reply[SEP_QUERY_REPLY_MAX];
    PTOKEN token;
    NTSTATUS status;

    memset(reply, 0, sizeof(reply));

    /* The retlen pre-write, then the fixed-length gate — both BEFORE the
     * class logic, exactly the unix-layer order (so a short TokenSource
     * buffer is BUFFER_TOO_SMALL while an adequate one reaches "no such
     * case" = NOT_IMPLEMENTED; sem_se/se_query pins both). */
    ULONG fixedLength = SepTokenInfoLength(infoClass);
    status = SepWriteReturnLength(returnLength, fixedLength);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (length < fixedLength)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    switch (infoClass)
    {
    case TokenUser:
    {
        status = SepReferenceTokenByHandle(tokenHandle, TOKEN_QUERY, &token, 0);
        /* the oracle's retlen on failure: 0 + sizeof(TOKEN_USER) */
        if (!NT_SUCCESS(status))
        {
            SepWriteReturnLength(returnLength, sizeof(TOKEN_USER));
            return status;
        }
        ULONG sidLength = token->userSidLength;
        ULONG needed = sizeof(TOKEN_USER) + sidLength;
        SepWriteReturnLength(returnLength, needed);
        if (length < needed)
        {
            ObDereferenceObject(token);
            return STATUS_BUFFER_TOO_SMALL;
        }
        TOKEN_USER *user = (TOKEN_USER *)reply;
        user->User.Sid = (PSID)((BYTE *)buffer + sizeof(TOKEN_USER));
        user->User.Attributes = 0;
        memcpy(reply + sizeof(TOKEN_USER), SepTokenUserSid(token), sidLength);
        ObDereferenceObject(token);
        return SepCopyToUser(buffer, reply, needed);
    }

    case TokenGroups:
    case TokenLogonSid:
    {
        status = SepReferenceTokenByHandle(tokenHandle, TOKEN_QUERY, &token, 0);
        if (!NT_SUCCESS(status))
        {
            SepWriteReturnLength(returnLength, 0);
            return status;
        }
        ULONG attrMask = infoClass == TokenLogonSid ? SE_GROUP_LOGON_ID : 0;
        ULONG *attrs = SepTokenGroupAttrs(token);
        ULONG count = 0, sidsLength = 0;
        for (ULONG i = 0; i < token->groupCount; i++)
        {
            if (attrMask != 0 && (attrs[i] & attrMask) == 0)
            {
                continue;
            }
            count++;
            sidsLength += SepSidLength(SepTokenGroupSid(token, i));
        }
        ULONG arrayEnd = (ULONG)offsetof(TOKEN_GROUPS, Groups) + count * sizeof(SID_AND_ATTRIBUTES);
        ULONG needed = arrayEnd + sidsLength;
        SepWriteReturnLength(returnLength, needed);
        if (length < needed)
        {
            ObDereferenceObject(token);
            return STATUS_BUFFER_TOO_SMALL;
        }
        ASSERT(needed <= sizeof(reply));
        TOKEN_GROUPS *groups = (TOKEN_GROUPS *)reply;
        groups->GroupCount = count;
        BYTE *sidCursor = reply + arrayEnd;
        BYTE *userSidCursor = (BYTE *)buffer + arrayEnd;
        ULONG out = 0;
        for (ULONG i = 0; i < token->groupCount; i++)
        {
            if (attrMask != 0 && (attrs[i] & attrMask) == 0)
            {
                continue;
            }
            SID *sid = SepTokenGroupSid(token, i);
            ULONG sidLength = SepSidLength(sid);
            groups->Groups[out].Attributes = attrs[i];
            groups->Groups[out].Sid = (PSID)userSidCursor;
            memcpy(sidCursor, sid, sidLength);
            sidCursor += sidLength;
            userSidCursor += sidLength;
            out++;
        }
        ObDereferenceObject(token);
        return SepCopyToUser(buffer, reply, needed);
    }

    case TokenOwner:
    case TokenPrimaryGroup:
    {
        status = SepReferenceTokenByHandle(tokenHandle, TOKEN_QUERY, &token, 0);
        if (!NT_SUCCESS(status))
        {
            SepWriteReturnLength(returnLength, sizeof(TOKEN_OWNER));
            return status;
        }
        /* owner == primary group in the boot identity (create_token sets
         * both from the primary-group index) */
        SID *sid = SepTokenGroupSid(token, token->primaryGroupIndex);
        ULONG sidLength = SepSidLength(sid);
        ULONG needed = sizeof(TOKEN_OWNER) + sidLength;
        SepWriteReturnLength(returnLength, needed);
        if (length < needed)
        {
            ObDereferenceObject(token);
            return STATUS_BUFFER_TOO_SMALL;
        }
        TOKEN_OWNER *owner = (TOKEN_OWNER *)reply;
        owner->Owner = (PSID)((BYTE *)buffer + sizeof(TOKEN_OWNER));
        memcpy(reply + sizeof(TOKEN_OWNER), sid, sidLength);
        ObDereferenceObject(token);
        return SepCopyToUser(buffer, reply, needed);
    }

    case TokenPrivileges:
    {
        status = SepReferenceTokenByHandle(tokenHandle, TOKEN_QUERY, &token, 0);
        ULONG headerLength = (ULONG)offsetof(TOKEN_PRIVILEGES, Privileges);
        if (!NT_SUCCESS(status))
        {
            SepWriteReturnLength(returnLength, headerLength);
            return status;
        }
        ULONG count = token->privilegeCount;
        ULONG needed = headerLength + count * (ULONG)sizeof(LUID_AND_ATTRIBUTES);
        SepWriteReturnLength(returnLength, needed);
        if (length < needed)
        {
            ObDereferenceObject(token);
            return STATUS_BUFFER_TOO_SMALL;
        }
        ASSERT(needed <= sizeof(reply));
        TOKEN_PRIVILEGES *result = (TOKEN_PRIVILEGES *)reply;
        result->PrivilegeCount = count;
        LUID_AND_ATTRIBUTES *out = (LUID_AND_ATTRIBUTES *)(reply + headerLength);
        PSEP_PRIVILEGE privileges = SepTokenPrivileges(token);
        for (ULONG i = 0; i < count; i++)
        {
            out[i].Luid = privileges[i].luid;
            out[i].Attributes =
                (privileges[i].enabled ? SE_PRIVILEGE_ENABLED : 0) |
                (privileges[i].enabledByDefault ? SE_PRIVILEGE_ENABLED_BY_DEFAULT : 0);
        }
        ObDereferenceObject(token);
        return SepCopyToUser(buffer, reply, needed);
    }

    case TokenDefaultDacl:
    {
        status = SepReferenceTokenByHandle(tokenHandle, TOKEN_QUERY, &token, 0);
        if (!NT_SUCCESS(status))
        {
            SepWriteReturnLength(returnLength, sizeof(TOKEN_DEFAULT_DACL));
            return status;
        }
        ULONG daclLength = SepTokenDefaultDaclLength(token);
        ULONG needed = sizeof(TOKEN_DEFAULT_DACL) + daclLength;
        SepWriteReturnLength(returnLength, needed);
        if (length < needed)
        {
            ObDereferenceObject(token);
            return STATUS_BUFFER_TOO_SMALL;
        }
        TOKEN_DEFAULT_DACL *result = (TOKEN_DEFAULT_DACL *)reply;
        result->DefaultDacl =
            daclLength != 0 ? (PACL)((BYTE *)buffer + sizeof(TOKEN_DEFAULT_DACL)) : 0;
        if (daclLength != 0)
        {
            memcpy(reply + sizeof(TOKEN_DEFAULT_DACL), SepTokenDefaultDacl(token), daclLength);
        }
        ObDereferenceObject(token);
        return SepCopyToUser(buffer, reply, needed);
    }

    case TokenImpersonationLevel:
    {
        status = SepReferenceTokenByHandle(tokenHandle, TOKEN_QUERY, &token, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        /* a primary token has no impersonation level (unix layer:
         * `reply->primary -> STATUS_INVALID_PARAMETER`) */
        if (token->primary)
        {
            ObDereferenceObject(token);
            return STATUS_INVALID_PARAMETER;
        }
        SECURITY_IMPERSONATION_LEVEL level =
            (SECURITY_IMPERSONATION_LEVEL)token->impersonationLevel;
        ObDereferenceObject(token);
        return SepCopyToUser(buffer, &level, sizeof(level));
    }

    case TokenStatistics:
    {
        status = SepReferenceTokenByHandle(tokenHandle, TOKEN_QUERY, &token, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        TOKEN_STATISTICS statistics;
        memset(&statistics, 0, sizeof(statistics));
        statistics.TokenId = token->tokenId;
        /* AuthenticationId 0, never-expiring expiration, Dynamic* 0: the
         * unix layer fabricates exactly these (NtQueryInformationToken
         * TokenStatistics case). */
        statistics.ExpirationTime.QuadPart = 0x7fffffffffffffffLL;
        statistics.TokenType = token->primary ? TokenPrimary : TokenImpersonation;
        statistics.ImpersonationLevel = (SECURITY_IMPERSONATION_LEVEL)token->impersonationLevel;
        statistics.GroupCount = token->groupCount;
        statistics.PrivilegeCount = token->privilegeCount;
        statistics.ModifiedId = token->modifiedId;
        ObDereferenceObject(token);
        return SepCopyToUser(buffer, &statistics, sizeof(statistics));
    }

    case TokenType:
    {
        status = SepReferenceTokenByHandle(tokenHandle, TOKEN_QUERY, &token, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        TOKEN_TYPE type = token->primary ? TokenPrimary : TokenImpersonation;
        ObDereferenceObject(token);
        return SepCopyToUser(buffer, &type, sizeof(type));
    }

    case TokenSessionId:
    {
        status = SepReferenceTokenByHandle(tokenHandle, TOKEN_QUERY, &token, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        DWORD sessionId = token->sessionId;
        ObDereferenceObject(token);
        return SepCopyToUser(buffer, &sessionId, sizeof(sessionId));
    }

    case TokenElevationType:
    {
        status = SepReferenceTokenByHandle(tokenHandle, TOKEN_QUERY, &token, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        TOKEN_ELEVATION_TYPE elevationType = (TOKEN_ELEVATION_TYPE)token->elevationType;
        ObDereferenceObject(token);
        return SepCopyToUser(buffer, &elevationType, sizeof(elevationType));
    }

    case TokenElevation:
    {
        status = SepReferenceTokenByHandle(tokenHandle, TOKEN_QUERY, &token, 0);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        /* Default-elevation tokens count as elevated iff the admins group
         * is present; otherwise only Full is (server/token.c
         * get_token_info). The boot line is Limited -> 0. */
        TOKEN_ELEVATION elevation;
        if (token->elevationType == TokenElevationTypeDefault)
        {
            elevation.TokenIsElevated =
                SepTokenSidPresent(token, SepSidOf(&SepBuiltinAdminsSid), FALSE);
        }
        else
        {
            elevation.TokenIsElevated = token->elevationType == TokenElevationTypeFull;
        }
        ObDereferenceObject(token);
        return SepCopyToUser(buffer, &elevation, sizeof(elevation));
    }

    /* The unix-side semi-stubs: answered WITHOUT touching the handle at
     * all — even an invalid handle succeeds on the oracle (the unix layer
     * never issues a server call for these). Mirror that. */
    case TokenVirtualizationEnabled:
    case TokenIsAppContainer:
    {
        DWORD value = 0;
        return SepCopyToUser(buffer, &value, sizeof(value));
    }

    case TokenUIAccess:
    {
        DWORD value = 1;
        return SepCopyToUser(buffer, &value, sizeof(value));
    }

    case TokenIntegrityLevel:
    {
        /* always the high mandatory label S-1-16-12288 (unix semi-stub) */
        TOKEN_MANDATORY_LABEL *label = (TOKEN_MANDATORY_LABEL *)reply;
        ULONG sidLength = SepSidLength(SepSidOf(&SepHighLabelSid));
        ULONG needed = sizeof(TOKEN_MANDATORY_LABEL) + sidLength;
        label->Label.Sid = (PSID)((BYTE *)buffer + sizeof(TOKEN_MANDATORY_LABEL));
        label->Label.Attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED;
        memcpy(reply + sizeof(TOKEN_MANDATORY_LABEL), SepSidOf(&SepHighLabelSid), sidLength);
        return SepCopyToUser(buffer, reply, needed);
    }

    case TokenAppContainerSid:
    {
        TOKEN_APPCONTAINER_INFORMATION info;
        info.TokenAppContainer = 0;
        return SepCopyToUser(buffer, &info, sizeof(info));
    }

    default:
        /* TokenSource, TokenRestrictedSids, TokenLinkedToken, and every
         * other class: unbuilt, refusing loudly (Art. 12). The oracle's
         * switch has no case for them either (TokenLinkedToken has one but
         * no baked caller — docs/03 CUI-2 notes), which makes the oracle
         * unbuilt here too — not a contract, so no test pins it. */
        return STATUS_NOT_IMPLEMENTED;
    }
}

/* --- NtAdjustPrivilegesToken ------------------------------------------------ */

/* Input privilege-count bound: wineserver bounds the request by its 64 KiB
 * message cap; anything a real caller sends is far below either. */
#define SEP_ADJUST_MAX_PRIVILEGES 1024

NTSTATUS NtAdjustPrivilegesToken(HANDLE tokenHandle, BOOLEAN disableAll, TOKEN_PRIVILEGES *newState,
                                 DWORD length, TOKEN_PRIVILEGES *previousState, DWORD *returnLength)
{
    NTSTATUS status;
    PTOKEN token;
    LUID_AND_ATTRIBUTES *input = 0;
    ULONG inputCount = 0;
    const ULONG headerLength = (ULONG)offsetof(TOKEN_PRIVILEGES, Privileges);

    /* +TOKEN_QUERY only when previous state is wanted (wineserver
     * adjust_token_privileges: get_modified_state adds it). */
    ACCESS_MASK access = TOKEN_ADJUST_PRIVILEGES;
    if (previousState != 0)
    {
        access |= TOKEN_QUERY;
    }

    if (!disableAll)
    {
        ULONG count;
        status = KiCopyFromUser(&count, &newState->PrivilegeCount, sizeof(count));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (count > SEP_ADJUST_MAX_PRIVILEGES)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (count != 0)
        {
            input = MiAllocatePool(count * sizeof(*input));
            if (input == 0)
            {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            status = KiCopyFromUser(input, newState->Privileges, count * sizeof(*input));
            if (!NT_SUCCESS(status))
            {
                MiFreePool(input);
                return status;
            }
        }
        inputCount = count;
    }

    status = SepReferenceTokenByHandle(tokenHandle, access, &token, 0);
    if (!NT_SUCCESS(status))
    {
        if (input != 0)
        {
            MiFreePool(input);
        }
        return status;
    }

    /* Previous-state budget: the FIT count of FOUND input privileges —
     * silent truncation, never BUFFER_TOO_SMALL (wineserver handler:
     * modified_priv_count = min(found, reply space)). */
    ULONG fit = 0;
    if (previousState != 0 && !disableAll)
    {
        ULONG found = 0;
        for (ULONG i = 0; i < inputCount; i++)
        {
            if (SepTokenFindPrivilege(token, input[i].Luid) != 0)
            {
                found++;
            }
        }
        ULONG space = length >= headerLength
                          ? (length - headerLength) / (ULONG)sizeof(LUID_AND_ATTRIBUTES)
                          : 0;
        fit = found < space ? found : space;
    }

    LUID_AND_ATTRIBUTES previous[8];
    LUID_AND_ATTRIBUTES *previousEntries = previous;
    BOOLEAN pooledPrevious = FALSE;
    if (fit > 8)
    {
        previousEntries = MiAllocatePool(fit * sizeof(*previousEntries));
        if (previousEntries == 0)
        {
            ObDereferenceObject(token);
            if (input != 0)
            {
                MiFreePool(input);
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        pooledPrevious = TRUE;
    }
    memset(previousEntries, 0, fit * sizeof(*previousEntries));

    /* Every adjust call re-allocates the modified id, even a no-op
     * (server/token.c token_adjust_privileges / token_disable_privileges). */
    token->modifiedId = SepAllocateLuid();

    NTSTATUS finalStatus = STATUS_SUCCESS;
    ULONG written = 0;
    if (disableAll)
    {
        PSEP_PRIVILEGE privileges = SepTokenPrivileges(token);
        for (ULONG i = 0; i < token->privilegeCount; i++)
        {
            privileges[i].enabled = FALSE;
        }
    }
    else
    {
        for (ULONG i = 0; i < inputCount; i++)
        {
            PSEP_PRIVILEGE privilege = SepTokenFindPrivilege(token, input[i].Luid);
            if (privilege == 0)
            {
                /* keep going; the ones that exist are still applied */
                finalStatus = STATUS_NOT_ALL_ASSIGNED;
                continue;
            }
            if (input[i].Attributes & SE_PRIVILEGE_REMOVED)
            {
                /* shrink in place: the trailing array only ever shrinks */
                PSEP_PRIVILEGE privileges = SepTokenPrivileges(token);
                ULONG index = (ULONG)(privilege - privileges);
                memmove(&privileges[index], &privileges[index + 1],
                        (token->privilegeCount - index - 1) * sizeof(SEP_PRIVILEGE));
                token->privilegeCount--;
            }
            else
            {
                if (written < fit)
                {
                    previousEntries[written].Luid = privilege->luid;
                    previousEntries[written].Attributes =
                        (privilege->enabled ? SE_PRIVILEGE_ENABLED : 0) |
                        (privilege->enabledByDefault ? SE_PRIVILEGE_ENABLED_BY_DEFAULT : 0);
                    written++;
                }
                privilege->enabled = (input[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
            }
        }
    }
    ObDereferenceObject(token);
    if (input != 0)
    {
        MiFreePool(input);
    }

    /* The previous-state reply: count and retlen describe the FIT (the
     * found-count truncated to the buffer), mirroring the oracle even when
     * removals leave fewer entries actually written. */
    if (previousState != 0)
    {
        ULONG replyLength = fit * (ULONG)sizeof(LUID_AND_ATTRIBUTES);
        status = KiProbeForWrite(previousState, headerLength + replyLength, sizeof(ULONG));
        if (NT_SUCCESS(status))
        {
            previousState->PrivilegeCount = fit;
            if (replyLength != 0)
            {
                memcpy(previousState->Privileges, previousEntries, replyLength);
            }
        }
        else
        {
            /* the adjustments above are already applied (the oracle's
             * server ran before its reply write, too); the caller still
             * learns its buffer was bad */
            finalStatus = status;
        }
        if (returnLength != 0)
        {
            NTSTATUS lengthStatus =
                KiProbeForWrite(returnLength, sizeof(*returnLength), sizeof(ULONG));
            if (NT_SUCCESS(lengthStatus))
            {
                *returnLength = headerLength + replyLength;
            }
            else
            {
                finalStatus = lengthStatus;
            }
        }
    }
    if (pooledPrevious)
    {
        MiFreePool(previousEntries);
    }
    return finalStatus;
}

/* --- NtPrivilegeCheck ------------------------------------------------------- */

NTSTATUS NtPrivilegeCheck(HANDLE tokenHandle, PRIVILEGE_SET *requiredPrivileges, BOOLEAN *result)
{
    NTSTATUS status;
    struct
    {
        DWORD PrivilegeCount;
        DWORD Control;
    } header;

    status = KiCopyFromUser(&header, requiredPrivileges, sizeof(header));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (header.PrivilegeCount > SEP_ADJUST_MAX_PRIVILEGES)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG entriesLength = header.PrivilegeCount * (ULONG)sizeof(LUID_AND_ATTRIBUTES);
    LUID_AND_ATTRIBUTES *entries = 0;
    if (header.PrivilegeCount != 0)
    {
        entries = MiAllocatePool(entriesLength);
        if (entries == 0)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        status = KiCopyFromUser(entries, requiredPrivileges->Privilege, entriesLength);
        if (!NT_SUCCESS(status))
        {
            MiFreePool(entries);
            return status;
        }
    }

    PTOKEN token;
    status = SepReferenceTokenByHandle(tokenHandle, TOKEN_QUERY, &token, 0);
    if (!NT_SUCCESS(status))
    {
        if (entries != 0)
        {
            MiFreePool(entries);
        }
        return status;
    }
    /* anonymous impersonation tokens can't be used; primary ones are fine
     * (wineserver check_token_privileges) */
    if (!token->primary && token->impersonationLevel <= SecurityAnonymous)
    {
        ObDereferenceObject(token);
        if (entries != 0)
        {
            MiFreePool(entries);
        }
        return STATUS_BAD_IMPERSONATION_LEVEL;
    }

    BOOLEAN has =
        SepTokenCheckPrivileges(token, (header.Control & PRIVILEGE_SET_ALL_NECESSARY) != 0, entries,
                                header.PrivilegeCount, entries);
    ObDereferenceObject(token);

    /* write the SE_PRIVILEGE_USED_FOR_ACCESS marks back into the caller's
     * array (the oracle's reply lands in privs->Privilege) */
    if (header.PrivilegeCount != 0)
    {
        status = KiProbeForWrite(requiredPrivileges->Privilege, entriesLength, sizeof(ULONG));
        if (NT_SUCCESS(status))
        {
            memcpy(requiredPrivileges->Privilege, entries, entriesLength);
        }
        MiFreePool(entries);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    status = KiProbeForWrite(result, sizeof(*result), sizeof(BOOLEAN));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    *result = has;
    return STATUS_SUCCESS;
}

/* --- NtDuplicateToken ------------------------------------------------------- */

NTSTATUS NtDuplicateToken(HANDLE existingToken, ACCESS_MASK desiredAccess,
                          POBJECT_ATTRIBUTES objectAttributes, BOOLEAN effectiveOnly,
                          TOKEN_TYPE tokenType, HANDLE *newTokenHandle)
{
    /* EffectiveOnly is ignored, as the oracle ignores it (unix
     * NtDuplicateToken FIXMEs it away). */
    (void)effectiveOnly;

    NTSTATUS status = SepPreZeroHandle(newTokenHandle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* Level from the SecurityQualityOfService, else SecurityAnonymous
     * (unix NtDuplicateToken). Handle attributes ride along. */
    LONG level = SecurityAnonymous;
    ULONG handleAttributes = 0;
    if (objectAttributes != 0)
    {
        OBJECT_ATTRIBUTES attributes;
        status = KiCopyFromUser(&attributes, objectAttributes, sizeof(attributes));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        handleAttributes = attributes.Attributes;
        if (attributes.SecurityQualityOfService != 0)
        {
            SECURITY_QUALITY_OF_SERVICE qos;
            status = KiCopyFromUser(&qos, attributes.SecurityQualityOfService, sizeof(qos));
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            level = (LONG)qos.ImpersonationLevel;
        }
    }

    PTOKEN source;
    OBJECT_HANDLE_INFORMATION handleInformation;
    status = SepReferenceTokenByHandle(existingToken, TOKEN_DUPLICATE, &source, &handleInformation);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PTOKEN duplicate;
    status = SepDuplicateToken(source, tokenType == TokenPrimary, level, &duplicate);
    if (!NT_SUCCESS(status))
    {
        ObDereferenceObject(source);
        return status;
    }

    /* access 0 inherits the source HANDLE's granted access (wineserver
     * duplicate_token: `req->access ? req->access : get_handle_access`) */
    ACCESS_MASK granted = desiredAccess != 0 ? ObpMapDesiredAccess(&SeTokenType, desiredAccess)
                                             : handleInformation.GrantedAccess;
    status = ObpCreateHandle(duplicate, granted, handleAttributes, newTokenHandle);
    /* drop the creator reference: on success the handle holds its own */
    ObDereferenceObject(duplicate);
    ObDereferenceObject(source);
    return status;
}

/* CUI-6: SetTokenInformation's back end. Only TokenDefaultDacl has real
 * semantics (dlls/ntdll/unix/security.c NtSetInformationToken); the length
 * is checked BEFORE the null-pointer test, a zero DACL clears it, and it
 * needs TOKEN_ADJUST_DEFAULT. TokenSessionId / TokenIntegrityLevel are
 * accepted no-ops (the oracle's pinned FIXME answer). Everything else
 * refuses loudly (Art. 12). */
/* CUI-6 filter/set-info capture bounds. SIDs are at most 8 subauthorities
 * (winnt.h SID_MAX_SUB_AUTHORITIES); the group/privilege caps bound a
 * malicious count so a huge value cannot exhaust the pool. */
#define SEP_MAX_ACL_LENGTH 65535
#define SEP_MAX_SID_LENGTH (8 + 4 * 15)
#define SEP_MAX_GROUPS     256
#define SEP_MAX_PRIVILEGES 256

NTSTATUS NtSetInformationToken(HANDLE tokenHandle, TOKEN_INFORMATION_CLASS infoClass, PVOID buffer,
                               ULONG length)
{
    switch (infoClass)
    {
    case TokenDefaultDacl:
    {
        if (length < sizeof(TOKEN_DEFAULT_DACL))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        TOKEN_DEFAULT_DACL header;
        NTSTATUS status = KiCopyFromUser(&header, buffer, sizeof(header));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        /* Capture the replacement ACL (a nested user pointer) up front. */
        PACL newDacl = 0;
        ULONG newDaclLength = 0;
        if (header.DefaultDacl != 0)
        {
            ACL aclHeader;
            status = KiCopyFromUser(&aclHeader, header.DefaultDacl, sizeof(ACL));
            if (!NT_SUCCESS(status))
            {
                return status;
            }
            newDaclLength = aclHeader.AclSize;
            if (newDaclLength < sizeof(ACL) || newDaclLength > SEP_MAX_ACL_LENGTH)
            {
                return STATUS_INVALID_ACL;
            }
            newDacl = MiAllocatePool(newDaclLength);
            if (newDacl == 0)
            {
                return STATUS_NO_MEMORY;
            }
            status = KiCopyFromUser(newDacl, header.DefaultDacl, newDaclLength);
            if (!NT_SUCCESS(status))
            {
                MiFreePool(newDacl);
                return status;
            }
        }
        PTOKEN token;
        status = SepReferenceTokenByHandle(tokenHandle, TOKEN_ADJUST_DEFAULT, &token, 0);
        if (!NT_SUCCESS(status))
        {
            if (newDacl != 0)
            {
                MiFreePool(newDacl);
            }
            return status;
        }
        /* Install as the side-allocated override (the one exception to the
         * shrink-only blob rule, se.h): free any prior override, abandon the
         * inline slot, and point at the new one — 0 means cleared. */
        if (token->defaultDaclOverride != 0)
        {
            MiFreePool(token->defaultDaclOverride);
        }
        token->defaultDaclOverride = newDacl;
        token->defaultDaclOverrideLength = newDaclLength;
        token->defaultDaclLength = 0; /* the inline slot no longer governs */
        token->modifiedId = SepAllocateLuid();
        ObDereferenceObject(token);
        return STATUS_SUCCESS;
    }
    case TokenSessionId:
    case TokenIntegrityLevel:
        /* The oracle's FIXME-success (dlls/ntdll/unix/security.c): a pinned
         * fixed answer, not a stub — no state here observes either. */
        return STATUS_SUCCESS;
    default:
        return STATUS_NOT_IMPLEMENTED;
    }
}

/* CUI-6: CreateRestrictedToken's back end. Needs TOKEN_DUPLICATE; the Flags
 * and RestrictedSids arguments are ignored exactly as the oracle ignores
 * them (dlls/ntdll/unix/security.c NtFilterToken FIXMEs). The new handle
 * carries the source handle's granted access. */
NTSTATUS NtFilterToken(HANDLE existingToken, ULONG flags, PTOKEN_GROUPS sidsToDisable,
                       PTOKEN_PRIVILEGES privilegesToDelete, PTOKEN_GROUPS restrictedSids,
                       PHANDLE newTokenHandle)
{
    (void)flags;          /* LUA_TOKEN etc. — ignored, as the oracle does */
    (void)restrictedSids; /* restricted-SID lists — ignored, as the oracle does */

    NTSTATUS status = SepPreZeroHandle(newTokenHandle);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* Capture the disable-SIDs into a contiguous blob (nested user SID
     * pointers) and the delete-LUIDs into a flat array. */
    BYTE *disableBlob = 0;
    ULONG disableCount = 0;
    if (sidsToDisable != 0)
    {
        ULONG count;
        status = KiCopyFromUser(&count, sidsToDisable, sizeof(count));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (count > 0 && count <= SEP_MAX_GROUPS)
        {
            disableBlob = MiAllocatePool(count * SEP_MAX_SID_LENGTH);
            if (disableBlob == 0)
            {
                return STATUS_NO_MEMORY;
            }
            BYTE *out = disableBlob;
            for (ULONG i = 0; i < count; i++)
            {
                SID_AND_ATTRIBUTES entry;
                status = KiCopyFromUser(&entry, &sidsToDisable->Groups[i], sizeof(entry));
                if (NT_SUCCESS(status) && entry.Sid != 0)
                {
                    SID sidHeader;
                    status = KiCopyFromUser(&sidHeader, entry.Sid, sizeof(SID));
                    if (NT_SUCCESS(status))
                    {
                        ULONG sidLen = SepSidLength(&sidHeader);
                        if (sidLen <= SEP_MAX_SID_LENGTH)
                        {
                            status = KiCopyFromUser(out, entry.Sid, sidLen);
                            out += sidLen;
                            disableCount++;
                        }
                    }
                }
                if (!NT_SUCCESS(status))
                {
                    MiFreePool(disableBlob);
                    return status;
                }
            }
        }
    }

    LUID *deleteLuids = 0;
    ULONG deleteCount = 0;
    if (privilegesToDelete != 0)
    {
        ULONG count;
        status = KiCopyFromUser(&count, privilegesToDelete, sizeof(count));
        if (!NT_SUCCESS(status))
        {
            if (disableBlob != 0)
            {
                MiFreePool(disableBlob);
            }
            return status;
        }
        if (count > 0 && count <= SEP_MAX_PRIVILEGES)
        {
            deleteLuids = MiAllocatePool(count * sizeof(LUID));
            if (deleteLuids == 0)
            {
                if (disableBlob != 0)
                {
                    MiFreePool(disableBlob);
                }
                return STATUS_NO_MEMORY;
            }
            for (ULONG i = 0; i < count; i++)
            {
                LUID_AND_ATTRIBUTES entry;
                status = KiCopyFromUser(&entry, &privilegesToDelete->Privileges[i], sizeof(entry));
                if (!NT_SUCCESS(status))
                {
                    MiFreePool(deleteLuids);
                    if (disableBlob != 0)
                    {
                        MiFreePool(disableBlob);
                    }
                    return status;
                }
                deleteLuids[deleteCount++] = entry.Luid;
            }
        }
    }

    PTOKEN source;
    OBJECT_HANDLE_INFORMATION handleInformation;
    status = SepReferenceTokenByHandle(existingToken, TOKEN_DUPLICATE, &source, &handleInformation);
    if (NT_SUCCESS(status))
    {
        PTOKEN filtered;
        status =
            SepFilterToken(source, disableBlob, disableCount, deleteLuids, deleteCount, &filtered);
        if (NT_SUCCESS(status))
        {
            /* The new handle inherits the source HANDLE's granted access. */
            status = ObpCreateHandle(filtered, handleInformation.GrantedAccess, 0, newTokenHandle);
            ObDereferenceObject(filtered);
        }
        ObDereferenceObject(source);
    }
    if (deleteLuids != 0)
    {
        MiFreePool(deleteLuids);
    }
    if (disableBlob != 0)
    {
        MiFreePool(disableBlob);
    }
    return status;
}

/* Find a token group by SID; returns its index or -1. */
static LONG SepTokenFindGroup(PTOKEN token, const SID *sid, ULONG sidLen)
{
    const BYTE *cursor = SepTokenGroupSids(token);
    for (ULONG i = 0; i < token->groupCount; i++)
    {
        const SID *group = (const SID *)cursor;
        ULONG groupLen = SepSidLength(group);
        if (groupLen == sidLen && memcmp(group, sid, sidLen) == 0)
        {
            return (LONG)i;
        }
        cursor += groupLen;
    }
    return -1;
}

/* CUI-6: NtAdjustGroupsToken — the AdjustTokenGroups back end
 * (beyond_oracle, sem_se/se_adjgroups; the oracle stubs it). ResetToDefault
 * restores every group's enabled-by-default state; otherwise each named
 * group's SE_GROUP_ENABLED bit is set/cleared, but an SE_GROUP_MANDATORY
 * group cannot be disabled (STATUS_CANT_DISABLE_MANDATORY, MS docs). The
 * fixed identity's groups are all mandatory-and-enabled, so no adjust ever
 * changes state — the previous-state buffer therefore reports zero groups,
 * which is the true previous state, not a fabrication (G12). */
NTSTATUS NtAdjustGroupsToken(HANDLE tokenHandle, BOOLEAN resetToDefault, PTOKEN_GROUPS newState,
                             ULONG bufferLength, PTOKEN_GROUPS previousState, PULONG returnLength)
{
    ACCESS_MASK access = TOKEN_ADJUST_GROUPS | (previousState != 0 ? TOKEN_QUERY : 0);

    /* Capture the requested groups (nested SIDs) up front. */
    BYTE *sidBlob = 0;
    ULONG *wantAttrs = 0;
    ULONG wantCount = 0;
    NTSTATUS status = STATUS_SUCCESS;
    if (!resetToDefault && newState != 0)
    {
        status = KiCopyFromUser(&wantCount, newState, sizeof(wantCount));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (wantCount > SEP_MAX_GROUPS)
        {
            return STATUS_INVALID_PARAMETER;
        }
        if (wantCount != 0)
        {
            sidBlob = MiAllocatePool(wantCount * SEP_MAX_SID_LENGTH);
            wantAttrs = MiAllocatePool(wantCount * sizeof(ULONG) + 1);
            if (sidBlob == 0 || wantAttrs == 0)
            {
                if (sidBlob != 0)
                    MiFreePool(sidBlob);
                if (wantAttrs != 0)
                    MiFreePool(wantAttrs);
                return STATUS_NO_MEMORY;
            }
            BYTE *out = sidBlob;
            for (ULONG i = 0; i < wantCount; i++)
            {
                SID_AND_ATTRIBUTES entry;
                status = KiCopyFromUser(&entry, &newState->Groups[i], sizeof(entry));
                if (NT_SUCCESS(status) && entry.Sid != 0)
                {
                    SID sidHeader;
                    status = KiCopyFromUser(&sidHeader, entry.Sid, sizeof(SID));
                    if (NT_SUCCESS(status))
                    {
                        ULONG sidLen = SepSidLength(&sidHeader);
                        if (sidLen <= SEP_MAX_SID_LENGTH)
                        {
                            status = KiCopyFromUser(out, entry.Sid, sidLen);
                            wantAttrs[i] = entry.Attributes;
                            out += sidLen;
                        }
                    }
                }
                if (!NT_SUCCESS(status))
                {
                    MiFreePool(sidBlob);
                    MiFreePool(wantAttrs);
                    return status;
                }
            }
        }
    }

    PTOKEN token;
    status = SepReferenceTokenByHandle(tokenHandle, access, &token, 0);
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }
    ULONG *attrs = SepTokenGroupAttrs(token);

    if (resetToDefault)
    {
        for (ULONG i = 0; i < token->groupCount; i++)
        {
            attrs[i] &= ~(ULONG)SE_GROUP_ENABLED;
            if (attrs[i] & SE_GROUP_ENABLED_BY_DEFAULT)
            {
                attrs[i] |= SE_GROUP_ENABLED;
            }
        }
    }
    else
    {
        /* Validation pass: a mandatory group cannot be disabled. */
        const BYTE *cursor = sidBlob;
        for (ULONG i = 0; i < wantCount; i++)
        {
            const SID *sid = (const SID *)cursor;
            ULONG sidLen = SepSidLength(sid);
            LONG idx = SepTokenFindGroup(token, sid, sidLen);
            if (idx >= 0 && (attrs[idx] & SE_GROUP_MANDATORY) && !(wantAttrs[i] & SE_GROUP_ENABLED))
            {
                status = STATUS_CANT_DISABLE_MANDATORY;
                ObDereferenceObject(token);
                goto cleanup;
            }
            cursor += sidLen;
        }
        /* Apply pass. */
        cursor = sidBlob;
        for (ULONG i = 0; i < wantCount; i++)
        {
            const SID *sid = (const SID *)cursor;
            ULONG sidLen = SepSidLength(sid);
            LONG idx = SepTokenFindGroup(token, sid, sidLen);
            if (idx >= 0)
            {
                if (wantAttrs[i] & SE_GROUP_ENABLED)
                {
                    attrs[idx] |= SE_GROUP_ENABLED;
                }
                else
                {
                    attrs[idx] &= ~(ULONG)SE_GROUP_ENABLED;
                }
            }
            cursor += sidLen;
        }
    }
    token->modifiedId = SepAllocateLuid();
    ObDereferenceObject(token);

    /* Previous state: no group on this fixed identity actually changes
     * enabled-state, so the true previous state is empty. */
    if (previousState != 0)
    {
        ULONG headerLength = (ULONG)offsetof(TOKEN_GROUPS, Groups);
        if (returnLength != 0)
        {
            ULONG needed = headerLength;
            status = SepCopyToUser(returnLength, &needed, sizeof(needed));
            if (!NT_SUCCESS(status))
            {
                goto cleanup;
            }
        }
        if (bufferLength < headerLength)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            goto cleanup;
        }
        DWORD zero = 0;
        status = SepCopyToUser(previousState, &zero, sizeof(zero));
    }

cleanup:
    if (sidBlob != 0)
    {
        MiFreePool(sidBlob);
    }
    if (wantAttrs != 0)
    {
        MiFreePool(wantAttrs);
    }
    return status;
}

/* CUI-6: NtImpersonateAnonymousToken — mint an ANONYMOUS LOGON (S-1-5-7)
 * impersonation token and attach it to the thread (beyond_oracle,
 * sem_se/se_impersonate + se_adjgroups; the oracle stubs it). Rides the same
 * ETHREAD.impersonationToken slot the ThreadImpersonationToken attach uses
 * (G11). */
NTSTATUS NtImpersonateAnonymousToken(HANDLE threadHandle)
{
    /* One group (World), no privileges, no default DACL; SecurityImpersonation
     * so NtOpenThreadToken does not refuse it as anonymous-level. */
    const SID *worldSid = SepSidOf(&SepWorldSid);
    ULONG worldLen = SepSidLength(worldSid);
    ULONG groupAttrs[1] = {SE_GROUP_MANDATORY | SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT};
    BYTE groupSids[SEP_MAX_SID_LENGTH];
    memcpy(groupSids, worldSid, worldLen);

    PTOKEN anon;
    NTSTATUS status = SepCreateToken(FALSE, SecurityImpersonation, 1, TokenElevationTypeLimited,
                                     SepSidOf(&SepAnonymousLogonSid), groupAttrs, groupSids,
                                     worldLen, 1, 0, 0, 0, 0, 0, 0, &anon);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PETHREAD thread;
    BOOLEAN referenced = FALSE;
    if (threadHandle == NtCurrentThread())
    {
        thread = KeGetCurrentThread()->threadObject;
    }
    else
    {
        PVOID body;
        status = ObReferenceObjectByHandle(threadHandle, THREAD_IMPERSONATE, &PspThreadType,
                                           ExGetPreviousMode(), &body, 0);
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(anon);
            return status;
        }
        thread = body;
        referenced = TRUE;
    }
    if (thread == 0)
    {
        ObDereferenceObject(anon);
        if (referenced)
        {
            ObDereferenceObject((PVOID)thread);
        }
        return STATUS_INVALID_HANDLE;
    }
    if (thread->impersonationToken != 0)
    {
        ObDereferenceObject(thread->impersonationToken);
    }
    thread->impersonationToken = anon; /* transfer the creator reference */
    if (referenced)
    {
        ObDereferenceObject(thread);
    }
    return STATUS_SUCCESS;
}
