/* kernel/se/access.c — NtAccessCheck: the wineserver ACE walk, exactly
 * (CUI-2). The algorithm is a step-by-step transcription of
 * third_party/wine server/token.c token_access_check + the unix layer's
 * argument protocol (dlls/ntdll/unix/security.c NtAccessCheck: the NULL
 * pre-checks, the PRIVILEGE_SET size floor, BUFFER_TOO_SMALL). Object-type
 * lists, restricted-SID walks and the audit/alarm variants stay
 * unimplemented, as they are on the oracle.
 */
#include "kernel/se/se.h"
#include "kernel/mm/pool.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

/* server/protocol map_access: expand generic bits per the caller's mapping,
 * then drop them. */
static ACCESS_MASK SepMapAccess(ACCESS_MASK access, const GENERIC_MAPPING *mapping)
{
    if (access & GENERIC_READ)
    {
        access |= mapping->GenericRead;
    }
    if (access & GENERIC_WRITE)
    {
        access |= mapping->GenericWrite;
    }
    if (access & GENERIC_EXECUTE)
    {
        access |= mapping->GenericExecute;
    }
    if (access & GENERIC_ALL)
    {
        access |= mapping->GenericAll;
    }
    return access & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

/* token_access_check (server/token.c), against the captured SD. On
 * STATUS_SUCCESS *accessStatus carries grant/deny; *privilege carries at
 * most one used privilege (SeSecurityPrivilege), *privilegeCount 0 or 1. */
static NTSTATUS SepTokenAccessCheck(PTOKEN token, PSEP_SECURITY_DESCRIPTOR sd,
                                    ACCESS_MASK desiredAccess, const GENERIC_MAPPING *mapping,
                                    LUID_AND_ATTRIBUTES *privilege, ULONG *privilegeCount,
                                    ACCESS_MASK *grantedAccess, NTSTATUS *accessStatus)
{
    ACCESS_MASK currentAccess = 0;
    ACCESS_MASK deniedAccess = 0;

    *grantedAccess = 0;

    /* 0: generic bits in the desired mask never reach the walk */
    if (desiredAccess & (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL))
    {
        *privilegeCount = 0;
        return STATUS_GENERIC_NOT_MAPPED;
    }

    const BYTE *cursor = SepSdData(sd);
    const SID *owner = sd->ownerLength != 0 ? (const SID *)cursor : 0;
    cursor += sd->ownerLength;
    const SID *group = sd->groupLength != 0 ? (const SID *)cursor : 0;
    cursor += sd->groupLength + sd->saclLength;
    const ACL *dacl = sd->daclLength != 0 ? (const ACL *)cursor : 0;
    BOOLEAN daclPresent = (sd->control & SE_DACL_PRESENT) != 0;

    if (owner == 0 || group == 0)
    {
        *privilegeCount = 0;
        return STATUS_INVALID_SECURITY_DESCR;
    }

    /* 1: an unprotected object grants everything asked */
    if (!daclPresent || dacl == 0)
    {
        *privilegeCount = 0;
        *grantedAccess = (desiredAccess & MAXIMUM_ALLOWED) ? mapping->GenericAll : desiredAccess;
        *accessStatus = STATUS_SUCCESS;
        return STATUS_SUCCESS;
    }

    /* 2: ACCESS_SYSTEM_SECURITY wants SeSecurityPrivilege, reported through
     * the privilege set */
    if (desiredAccess & ACCESS_SYSTEM_SECURITY)
    {
        LUID_AND_ATTRIBUTES securityPrivilege;
        securityPrivilege.Luid.LowPart = SE_SECURITY_PRIVILEGE;
        securityPrivilege.Luid.HighPart = 0;
        securityPrivilege.Attributes = 0;
        LUID_AND_ATTRIBUTES used = securityPrivilege;
        if (SepTokenCheckPrivileges(token, TRUE, &securityPrivilege, 1, &used))
        {
            if (*privilegeCount >= 1)
            {
                *privilegeCount = 1;
                *privilege = used;
            }
            else
            {
                *privilegeCount = 1;
                return STATUS_BUFFER_TOO_SMALL;
            }
            currentAccess |= ACCESS_SYSTEM_SECURITY;
            if (desiredAccess == currentAccess)
            {
                *grantedAccess = currentAccess;
                *accessStatus = STATUS_SUCCESS;
                return STATUS_SUCCESS;
            }
        }
        else
        {
            *privilegeCount = 0;
            *accessStatus = STATUS_PRIVILEGE_NOT_HELD;
            return STATUS_SUCCESS;
        }
    }
    else
    {
        *privilegeCount = 0;
    }

    /* 3: the owner short-circuit (SeTakeOwnershipPrivilege is a set-owner
     * concern, not checked here — server comment) */
    if (SepTokenSidPresent(token, owner, FALSE))
    {
        currentAccess |= STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE;
        if (desiredAccess == currentAccess)
        {
            *grantedAccess = currentAccess;
            *accessStatus = STATUS_SUCCESS;
            return STATUS_SUCCESS;
        }
    }

    /* 4: the deny/allow ACE walk */
    ULONG offset = sizeof(ACL);
    for (ULONG i = 0; i < dacl->AceCount; i++)
    {
        const ACE_HEADER *ace = (const ACE_HEADER *)((const BYTE *)dacl + offset);
        offset += ace->AceSize;
        const SID *sid =
            (const SID *)((const BYTE *)ace + sizeof(ACE_HEADER) + sizeof(ACCESS_MASK));

        if (ace->AceFlags & INHERIT_ONLY_ACE)
        {
            continue;
        }
        switch (ace->AceType)
        {
        case ACCESS_DENIED_ACE_TYPE:
            if (SepTokenSidPresent(token, sid, TRUE))
            {
                ACCESS_MASK access = SepMapAccess(
                    *(const ACCESS_MASK *)((const BYTE *)ace + sizeof(ACE_HEADER)), mapping);
                if (desiredAccess & MAXIMUM_ALLOWED)
                {
                    deniedAccess |= access;
                }
                else
                {
                    deniedAccess |= (access & ~currentAccess);
                    if (desiredAccess & access)
                    {
                        goto done;
                    }
                }
            }
            break;
        case ACCESS_ALLOWED_ACE_TYPE:
            if (SepTokenSidPresent(token, sid, FALSE))
            {
                ACCESS_MASK access = SepMapAccess(
                    *(const ACCESS_MASK *)((const BYTE *)ace + sizeof(ACE_HEADER)), mapping);
                if (desiredAccess & MAXIMUM_ALLOWED)
                {
                    currentAccess |= access;
                }
                else
                {
                    currentAccess |= (access & ~deniedAccess);
                }
            }
            break;
        default:
            break;
        }
        /* the server's own early-out (only ever fires for desired == 0) */
        if (desiredAccess == *grantedAccess)
        {
            break;
        }
    }

done:
    if (desiredAccess & MAXIMUM_ALLOWED)
    {
        *grantedAccess = currentAccess & ~deniedAccess;
    }
    else if ((currentAccess & desiredAccess) == desiredAccess)
    {
        *grantedAccess = currentAccess & desiredAccess;
    }
    else
    {
        *grantedAccess = 0;
    }
    *accessStatus = *grantedAccess != 0 ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    return STATUS_SUCCESS;
}

NTSTATUS NtAccessCheck(PSECURITY_DESCRIPTOR securityDescriptor, HANDLE tokenHandle,
                       ACCESS_MASK desiredAccess, PGENERIC_MAPPING genericMapping,
                       PPRIVILEGE_SET privilegeSet, PULONG privilegeSetLength, PULONG grantedAccess,
                       NTSTATUS *accessStatus)
{
    NTSTATUS status;

    /* the unix layer's pre-checks, verbatim */
    if (privilegeSet == 0 || privilegeSetLength == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    ULONG privilegeLength;
    status = KiCopyFromUser(&privilegeLength, privilegeSetLength, sizeof(privilegeLength));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    GENERIC_MAPPING mapping;
    status = KiCopyFromUser(&mapping, genericMapping, sizeof(mapping));
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PSEP_SECURITY_DESCRIPTOR sd;
    status = SepCaptureSecurityDescriptor(securityDescriptor, &sd);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    PTOKEN token;
    status = SepReferenceTokenByHandle(tokenHandle, TOKEN_QUERY, &token, 0);
    if (!NT_SUCCESS(status))
    {
        MiFreePool(sd);
        return status;
    }
    /* only non-anonymous impersonation tokens may be checked against
     * (wineserver access_check) */
    if (token->primary)
    {
        status = STATUS_NO_IMPERSONATION_TOKEN;
        goto out;
    }
    if (token->impersonationLevel <= SecurityAnonymous)
    {
        status = STATUS_BAD_IMPERSONATION_LEVEL;
        goto out;
    }

    LUID_AND_ATTRIBUTES privilege;
    memset(&privilege, 0, sizeof(privilege));
    ULONG privilegeCount = 1;
    ACCESS_MASK granted = 0;
    NTSTATUS accessResult = STATUS_SUCCESS;
    status = SepTokenAccessCheck(token, sd, desiredAccess, &mapping, &privilege, &privilegeCount,
                                 &granted, &accessResult);
    if (!NT_SUCCESS(status))
    {
        goto out;
    }

    /* the reply-size protocol: *privilegeSetLength out is always at least
     * sizeof(PRIVILEGE_SET); a smaller in-buffer is BUFFER_TOO_SMALL and
     * nothing else is written (unix NtAccessCheck) */
    ULONG privilegesLength = privilegeCount * (ULONG)sizeof(LUID_AND_ATTRIBUTES);
    ULONG needed = (ULONG)offsetof(PRIVILEGE_SET, Privilege) + privilegesLength;
    if (needed < sizeof(PRIVILEGE_SET))
    {
        needed = sizeof(PRIVILEGE_SET);
    }
    status = KiProbeForWrite(privilegeSetLength, sizeof(*privilegeSetLength), sizeof(ULONG));
    if (!NT_SUCCESS(status))
    {
        goto out;
    }
    *privilegeSetLength = needed;
    if (privilegeLength < needed)
    {
        status = STATUS_BUFFER_TOO_SMALL;
        goto out;
    }

    status = KiProbeForWrite(
        privilegeSet, (ULONG)offsetof(PRIVILEGE_SET, Privilege) + privilegesLength, sizeof(ULONG));
    if (!NT_SUCCESS(status))
    {
        goto out;
    }
    privilegeSet->PrivilegeCount = privilegeCount;
    if (privilegeCount != 0)
    {
        memcpy(privilegeSet->Privilege, &privilege, privilegesLength);
    }

    status = KiProbeForWrite(grantedAccess, sizeof(*grantedAccess), sizeof(ULONG));
    if (!NT_SUCCESS(status))
    {
        goto out;
    }
    *grantedAccess = granted;
    status = KiProbeForWrite(accessStatus, sizeof(*accessStatus), sizeof(ULONG));
    if (!NT_SUCCESS(status))
    {
        goto out;
    }
    *accessStatus = accessResult;
    status = STATUS_SUCCESS;

out:
    ObDereferenceObject(token);
    MiFreePool(sd);
    return status;
}

/* CUI-6: the Ob create/open access authority — wineserver check_object_access
 * (server/token.c). An object with no security descriptor stays permissive
 * (the caller's mapped access is granted, MAXIMUM_ALLOWED already resolved to
 * the type's full mask by ObpMapDesiredAccess); an object that carries one
 * gets the real DACL ACE walk against the effective token
 * (SeCurrentToken = thread impersonation token else process token). This is
 * the retirement of the always-allow shortcut for SD-bearing objects.
 *
 * The mapping is the type's own GENERIC_MAPPING; a type without an explicit
 * one falls back to {read,write,exec}=STANDARD_RIGHTS_* and all=validAccess,
 * so a generic ACE still resolves within the type's rights (no baked caller
 * puts a generic ACE on such a type — docs/03). */
NTSTATUS SeCheckObjectAccess(POBJECT_TYPE type, PVOID securityDescriptor,
                             ACCESS_MASK desiredAccess, ACCESS_MASK mappedAccess,
                             ACCESS_MASK *grantedAccess)
{
    if (securityDescriptor == 0)
    {
        *grantedAccess = mappedAccess;
        return STATUS_SUCCESS;
    }
    GENERIC_MAPPING mapping;
    if (type->genericAll != 0)
    {
        mapping.GenericRead = type->genericRead;
        mapping.GenericWrite = type->genericWrite;
        mapping.GenericExecute = type->genericExecute;
        mapping.GenericAll = type->genericAll;
    }
    else
    {
        mapping.GenericRead = STANDARD_RIGHTS_READ;
        mapping.GenericWrite = STANDARD_RIGHTS_WRITE;
        mapping.GenericExecute = STANDARD_RIGHTS_EXECUTE;
        mapping.GenericAll = type->validAccess;
    }
    /* Expand generic bits before the walk (it refuses them); MAXIMUM_ALLOWED
     * is resolved inside SepTokenAccessCheck. */
    ACCESS_MASK expanded = SepMapAccess(desiredAccess, &mapping);
    LUID_AND_ATTRIBUTES privilege;
    memset(&privilege, 0, sizeof(privilege));
    ULONG privilegeCount = 1;
    ACCESS_MASK granted = 0;
    NTSTATUS accessResult = STATUS_SUCCESS;
    NTSTATUS status =
        SepTokenAccessCheck(SeCurrentToken(), securityDescriptor, expanded, &mapping, &privilege,
                            &privilegeCount, &granted, &accessResult);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (!NT_SUCCESS(accessResult))
    {
        return accessResult;
    }
    *grantedAccess = granted;
    return STATUS_SUCCESS;
}
