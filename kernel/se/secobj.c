/* kernel/se/secobj.c — NtQuerySecurityObject / NtSetSecurityObject (CUI-2).
 *
 * Ob owns the storage (OBJECT_HEADER.securityDescriptor, a SEP blob freed
 * with the object); Se owns the interpretation. Semantics are wineserver's:
 * get/set_security_object (server/handle.c: the per-info-bit access
 * requirements, part filtering) and set_sd_defaults_from_token
 * (server/object.c: parts missing from the incoming SD keep the stored ones,
 * else default from the current process token — owner from the token owner,
 * group from its primary group, DACL from its default DACL). An object with
 * no stored SD answers the zeroed 20-byte self-relative header, exactly as
 * the unix layer synthesizes it (dlls/ntdll/unix/security.c
 * NtQuerySecurityObject). Mandatory-label extraction/replacement
 * (LABEL_SECURITY_INFORMATION SACL surgery) has no baked caller and is not
 * reproduced (docs/03 CUI-2 notes).
 */
#include "kernel/se/se.h"
#include "kernel/mm/pool.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

NTSTATUS NtQuerySecurityObject(HANDLE handle, SECURITY_INFORMATION securityInformation,
                               PSECURITY_DESCRIPTOR descriptor, ULONG length, PULONG returnLength)
{
    /* READ_CONTROL to query; the SACL additionally wants
     * ACCESS_SYSTEM_SECURITY (server/handle.c get_security_object). */
    ACCESS_MASK access = READ_CONTROL;
    if (securityInformation & SACL_SECURITY_INFORMATION)
    {
        access |= ACCESS_SYSTEM_SECURITY;
    }
    PVOID body;
    NTSTATUS status = ObReferenceObjectByHandle(handle, access, 0, ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    PSEP_SECURITY_DESCRIPTOR stored = ObpGetHeader(body)->securityDescriptor;

    /* Filter the parts by the asked-for info bits; the control word passes
     * through unfiltered (plus SE_SELF_RELATIVE). */
    ULONG ownerLength = 0, groupLength = 0, saclLength = 0, daclLength = 0;
    USHORT control = 0;
    if (stored != 0)
    {
        control = stored->control;
        if (securityInformation & OWNER_SECURITY_INFORMATION)
        {
            ownerLength = stored->ownerLength;
        }
        if (securityInformation & GROUP_SECURITY_INFORMATION)
        {
            groupLength = stored->groupLength;
        }
        if ((securityInformation & SACL_SECURITY_INFORMATION) &&
            (stored->control & SE_SACL_PRESENT))
        {
            saclLength = stored->saclLength;
        }
        if ((securityInformation & DACL_SECURITY_INFORMATION) &&
            (stored->control & SE_DACL_PRESENT))
        {
            daclLength = stored->daclLength;
        }
    }

    ULONG needed = (ULONG)sizeof(SECURITY_DESCRIPTOR_RELATIVE) + ownerLength + groupLength +
                   saclLength + daclLength;
    if (returnLength != 0)
    {
        status = KiProbeForWrite(returnLength, sizeof(*returnLength), sizeof(ULONG));
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(body);
            return status;
        }
        *returnLength = needed;
    }
    if (length < needed)
    {
        ObDereferenceObject(body);
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Build the self-relative reply: header, then owner, group, sacl, dacl
     * in that order (the same order the parts are stored in).
     *
     * Pooled and sized to `needed`, not a fixed stack array. `needed` is
     * derived entirely from a descriptor the CALLER stored earlier, and
     * SepCaptureAcl accepts an ACL of up to 65535 bytes, so no constant is
     * large enough. The `length < needed` test above does not bound it
     * either -- the caller simply supplies a big enough output buffer. This
     * was previously BYTE reply[512] under an ASSERT, i.e. an unprivileged
     * halt of the machine (ASSERT is always compiled in and fatal) and a
     * 64 KiB stack overflow if that assert were ever relaxed. */
    BYTE *reply = MiAllocatePool(needed);
    if (reply == 0)
    {
        ObDereferenceObject(body);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    SECURITY_DESCRIPTOR_RELATIVE *header = (SECURITY_DESCRIPTOR_RELATIVE *)reply;
    memset(header, 0, sizeof(*header));
    header->Revision = SECURITY_DESCRIPTOR_REVISION;
    header->Control = control | SE_SELF_RELATIVE;
    ULONG offset = sizeof(*header);
    if (stored != 0)
    {
        const BYTE *parts = SepSdData(stored);
        if (ownerLength != 0)
        {
            header->Owner = offset;
            memcpy(reply + offset, parts, ownerLength);
            offset += ownerLength;
        }
        parts += stored->ownerLength;
        if (groupLength != 0)
        {
            header->Group = offset;
            memcpy(reply + offset, parts, groupLength);
            offset += groupLength;
        }
        parts += stored->groupLength;
        if (saclLength != 0)
        {
            header->Sacl = offset;
            memcpy(reply + offset, parts, saclLength);
            offset += saclLength;
        }
        parts += stored->saclLength;
        if (daclLength != 0)
        {
            header->Dacl = offset;
            memcpy(reply + offset, parts, daclLength);
            offset += daclLength;
        }
    }
    ObDereferenceObject(body);

    status = KiProbeForWrite(descriptor, needed, sizeof(ULONG));
    if (!NT_SUCCESS(status))
    {
        MiFreePool(reply);
        return status;
    }
    memcpy(descriptor, reply, needed);
    MiFreePool(reply);
    return STATUS_SUCCESS;
}

NTSTATUS NtSetSecurityObject(HANDLE handle, SECURITY_INFORMATION securityInformation,
                             PSECURITY_DESCRIPTOR descriptor)
{
    if (descriptor == 0)
    {
        return STATUS_ACCESS_VIOLATION;
    }

    PSEP_SECURITY_DESCRIPTOR incoming;
    NTSTATUS status = SepCaptureSecurityDescriptor(descriptor, &incoming);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* Demanding an owner/group part the SD does not carry is
     * INVALID_SECURITY_DESCR (the unix layer's pre-check). */
    if ((securityInformation & OWNER_SECURITY_INFORMATION) && incoming->ownerLength == 0)
    {
        MiFreePool(incoming);
        return STATUS_INVALID_SECURITY_DESCR;
    }
    if ((securityInformation & GROUP_SECURITY_INFORMATION) && incoming->groupLength == 0)
    {
        MiFreePool(incoming);
        return STATUS_INVALID_SECURITY_DESCR;
    }
    /* The unix layer forces the PRESENT bits for the parts being set. */
    if (securityInformation & (SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION))
    {
        incoming->control |= SE_SACL_PRESENT;
    }
    if (securityInformation & DACL_SECURITY_INFORMATION)
    {
        incoming->control |= SE_DACL_PRESENT;
    }

    /* Per-info-bit access requirements (server/handle.c set_security_object). */
    ACCESS_MASK access = 0;
    if (securityInformation &
        (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION))
    {
        access |= WRITE_OWNER;
    }
    if (securityInformation & SACL_SECURITY_INFORMATION)
    {
        access |= ACCESS_SYSTEM_SECURITY;
    }
    if (securityInformation & DACL_SECURITY_INFORMATION)
    {
        access |= WRITE_DAC;
    }
    PVOID body;
    status = ObReferenceObjectByHandle(handle, access, 0, ExGetPreviousMode(), &body, 0);
    if (!NT_SUCCESS(status))
    {
        MiFreePool(incoming);
        return status;
    }
    POBJECT_HEADER header = ObpGetHeader(body);
    PSEP_SECURITY_DESCRIPTOR stored = header->securityDescriptor;
    PTOKEN token = SeCurrentToken();

    /* The merge (server/object.c set_sd_defaults_from_token): each part
     * comes from the incoming SD when its info bit is set and the part is
     * there, else from the stored SD, else (owner/group/dacl) defaults from
     * the current process token. The control word starts from the INCOMING
     * SD's control; stored non-PRESENT control bits do not survive a set. */
    const BYTE *incomingParts = SepSdData(incoming);
    const BYTE *incomingOwner = incomingParts;
    const BYTE *incomingGroup = incomingOwner + incoming->ownerLength;
    const BYTE *incomingSacl = incomingGroup + incoming->groupLength;
    const BYTE *incomingDacl = incomingSacl + incoming->saclLength;
    const BYTE *storedParts = stored != 0 ? SepSdData(stored) : 0;
    const BYTE *storedOwner = storedParts;
    const BYTE *storedGroup = stored != 0 ? storedOwner + stored->ownerLength : 0;
    const BYTE *storedSacl = stored != 0 ? storedGroup + stored->groupLength : 0;
    const BYTE *storedDacl = stored != 0 ? storedSacl + stored->saclLength : 0;

    USHORT control =
        incoming->control & ~SE_SELF_RELATIVE & ~(USHORT)(SE_SACL_PRESENT | SE_DACL_PRESENT);
    const void *owner;
    ULONG ownerLength;
    if ((securityInformation & OWNER_SECURITY_INFORMATION) && incoming->ownerLength != 0)
    {
        owner = incomingOwner;
        ownerLength = incoming->ownerLength;
    }
    else if (stored != 0 && stored->ownerLength != 0)
    {
        owner = storedOwner;
        ownerLength = stored->ownerLength;
    }
    else
    {
        owner = SepTokenGroupSid(token, token->primaryGroupIndex);
        ownerLength = SepSidLength(owner);
    }

    const void *group;
    ULONG groupLength;
    if ((securityInformation & GROUP_SECURITY_INFORMATION) && incoming->groupLength != 0)
    {
        group = incomingGroup;
        groupLength = incoming->groupLength;
    }
    else if (stored != 0 && stored->groupLength != 0)
    {
        group = storedGroup;
        groupLength = stored->groupLength;
    }
    else
    {
        group = SepTokenGroupSid(token, token->primaryGroupIndex);
        groupLength = SepSidLength(group);
    }

    const void *sacl = 0;
    ULONG saclLength = 0;
    if ((securityInformation & SACL_SECURITY_INFORMATION) && (incoming->control & SE_SACL_PRESENT))
    {
        control |= SE_SACL_PRESENT;
        sacl = incomingSacl;
        saclLength = incoming->saclLength;
    }
    else if (stored != 0 && (stored->control & SE_SACL_PRESENT))
    {
        control |= SE_SACL_PRESENT;
        sacl = storedSacl;
        saclLength = stored->saclLength;
    }

    const void *dacl = 0;
    ULONG daclLength = 0;
    if ((securityInformation & DACL_SECURITY_INFORMATION) && (incoming->control & SE_DACL_PRESENT))
    {
        control |= SE_DACL_PRESENT;
        dacl = incomingDacl;
        daclLength = incoming->daclLength;
    }
    else if (stored != 0 && (stored->control & SE_DACL_PRESENT))
    {
        control |= SE_DACL_PRESENT;
        dacl = storedDacl;
        daclLength = stored->daclLength;
    }
    else
    {
        ACL *tokenDacl = SepTokenDefaultDacl(token);
        if (tokenDacl != 0)
        {
            control |= SE_DACL_PRESENT;
            dacl = tokenDacl;
            daclLength = token->defaultDaclLength;
        }
    }

    PSEP_SECURITY_DESCRIPTOR merged =
        MiAllocatePool(sizeof(*merged) + ownerLength + groupLength + saclLength + daclLength);
    if (merged == 0)
    {
        ObDereferenceObject(body);
        MiFreePool(incoming);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    merged->control = control;
    merged->ownerLength = ownerLength;
    merged->groupLength = groupLength;
    merged->saclLength = saclLength;
    merged->daclLength = daclLength;
    BYTE *cursor = SepSdData(merged);
    memcpy(cursor, owner, ownerLength);
    cursor += ownerLength;
    memcpy(cursor, group, groupLength);
    cursor += groupLength;
    if (saclLength != 0)
    {
        memcpy(cursor, sacl, saclLength);
        cursor += saclLength;
    }
    if (daclLength != 0)
    {
        memcpy(cursor, dacl, daclLength);
    }

    /* Ownership audit (G11): the header owns exactly one stored blob; the
     * old one dies here, the object's delete path frees the last one. */
    if (stored != 0)
    {
        MiFreePool(stored);
    }
    header->securityDescriptor = merged;
    ObDereferenceObject(body);
    MiFreePool(incoming);
    return STATUS_SUCCESS;
}
