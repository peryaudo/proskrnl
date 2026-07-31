/* kernel/se/sd.c — security-descriptor capture and validation (CUI-2).
 *
 * Callers hand NtAccessCheck / NtSetSecurityObject a SECURITY_DESCRIPTOR in
 * either form — absolute (kernel-side pointers... user pointers here) or
 * self-relative (offsets) — distinguished by the SE_SELF_RELATIVE control
 * bit. On the oracle ntdll's alloc_object_attributes normalizes before the
 * server sees it; on proskrnl the raw caller pointer arrives at the kernel,
 * so both forms are captured here into the SEP blob (wineserver's internal
 * `struct security_descriptor` shape: header + owner/group/sacl/dacl parts
 * packed in that order, control never carrying SE_SELF_RELATIVE).
 *
 * These parsers chew attacker-shaped variable-length structures: every
 * length is validated against wineserver's own rules (sd_is_valid /
 * acl_is_valid, server/token.c) before a single byte is trusted, and
 * malformed input answers STATUS_ACCESS_VIOLATION exactly as the server
 * answers an invalid inline SD.
 */
#include "kernel/se/se.h"
#include "kernel/mm/pool.h"
#include "kernel/syscall/uaccess.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

/* wineserver bounds an ACL to what a WORD can carry
 * (include/wine/server_protocol.h MAX_ACL_LEN). */
#define SEP_MAX_ACL_LENGTH 65535

BOOLEAN SepIsValidSid(const SID *sid, ULONG availableLength)
{
    if (availableLength < sizeof(SID) - sizeof(DWORD))
    {
        return FALSE;
    }
    if (sid->Revision != SID_REVISION || sid->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES)
    {
        return FALSE;
    }
    return SepSidLength(sid) <= availableLength;
}

/* The wineserver acl_is_valid walk (server/token.c): revision in range,
 * every ACE inside the ACL, known ACE types carrying a valid SID. */
BOOLEAN SepIsValidAcl(const ACL *acl, ULONG availableLength)
{
    if (availableLength < sizeof(ACL) || availableLength > SEP_MAX_ACL_LENGTH)
    {
        return FALSE;
    }
    if (acl->AclRevision < MIN_ACL_REVISION || acl->AclRevision > MAX_ACL_REVISION)
    {
        return FALSE;
    }
    if (acl->AclSize < sizeof(ACL) || acl->AclSize > availableLength)
    {
        return FALSE;
    }
    ULONG offset = sizeof(ACL);
    for (ULONG i = 0; i < acl->AceCount; i++)
    {
        if (offset + sizeof(ACE_HEADER) > acl->AclSize)
        {
            return FALSE;
        }
        const ACE_HEADER *ace = (const ACE_HEADER *)((const BYTE *)acl + offset);
        if (ace->AceSize < sizeof(ACE_HEADER) || offset + ace->AceSize > acl->AclSize)
        {
            return FALSE;
        }
        switch (ace->AceType)
        {
        case ACCESS_ALLOWED_ACE_TYPE:
        case ACCESS_DENIED_ACE_TYPE:
        case SYSTEM_AUDIT_ACE_TYPE:
        case SYSTEM_ALARM_ACE_TYPE:
        case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
        {
            ULONG sidOffset = sizeof(ACE_HEADER) + sizeof(ACCESS_MASK);
            if (ace->AceSize < sidOffset + sizeof(SID) - sizeof(DWORD))
            {
                return FALSE;
            }
            const SID *sid = (const SID *)((const BYTE *)ace + sidOffset);
            if (!SepIsValidSid(sid, ace->AceSize - sidOffset))
            {
                return FALSE;
            }
            break;
        }
        default:
            /* An unknown ACE type is INVALID. The comment used to claim the
             * server's walk accepts them; it does not -- third_party/wine
             * server/token.c acl_is_valid ends its switch with
             * `default: return FALSE;` (docs/review-2026-07 §9). Accepting
             * one meant the access check silently skipped an ACE that might
             * have been a deny. */
            return FALSE;
        }
        offset += ace->AceSize;
    }
    return TRUE;
}

/* Capture one SID part from user memory into `destination` (0 to just
 * measure). *length is the validated on-wire size.
 *
 * `capacity` is the room at `destination`, i.e. what the measure pass said
 * this part was. It is checked BEFORE the copy, and that ordering is the
 * whole point: the length lives in user memory and is re-read here, so a
 * sibling thread that grows the SID between the two passes would otherwise
 * have this copy run past a pool block sized by the first one
 * (docs/review-2026-07 §1d). Ignored while measuring. */
static NTSTATUS SepCaptureSid(const void *userSid, BYTE *destination, ULONG *length, ULONG capacity)
{
    SID header;
    NTSTATUS status = KiCopyFromUser(&header, userSid, sizeof(SID) - sizeof(DWORD));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (header.Revision != SID_REVISION || header.SubAuthorityCount > SID_MAX_SUB_AUTHORITIES)
    {
        return STATUS_ACCESS_VIOLATION;
    }
    ULONG sidLength = SepSidLength(&header);
    if (destination != 0)
    {
        if (sidLength != capacity)
        {
            return STATUS_ACCESS_VIOLATION; /* raced between the passes */
        }
        status = KiCopyFromUser(destination, userSid, sidLength);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }
    *length = sidLength;
    return STATUS_SUCCESS;
}

/* Capture one ACL part; validates the full ACE walk after the copy.
 * `capacity` as for SepCaptureSid, and checked before the copy for the same
 * reason -- an ACL is up to 65535 bytes, so this is the wider of the two. */
static NTSTATUS SepCaptureAcl(const void *userAcl, BYTE *destination, ULONG *length, ULONG capacity)
{
    ACL header;
    NTSTATUS status = KiCopyFromUser(&header, userAcl, sizeof(ACL));
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    if (header.AclSize < sizeof(ACL))
    {
        return STATUS_ACCESS_VIOLATION;
    }
    if (destination != 0)
    {
        if (header.AclSize != capacity)
        {
            return STATUS_ACCESS_VIOLATION; /* raced between the passes */
        }
        status = KiCopyFromUser(destination, userAcl, header.AclSize);
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        if (!SepIsValidAcl((const ACL *)destination, header.AclSize))
        {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    *length = header.AclSize;
    return STATUS_SUCCESS;
}

/* The four parts of a caller SD, as user pointers + presence, either form. */
typedef struct SEP_SD_PARTS
{
    USHORT control;
    const void *owner;
    const void *group;
    const void *sacl;
    const void *dacl;
} SEP_SD_PARTS;

static NTSTATUS SepResolveSdParts(PSECURITY_DESCRIPTOR userSd, SEP_SD_PARTS *parts)
{
    /* The common 4-byte prefix (Revision/Sbz1/Control) decides the form. */
    SECURITY_DESCRIPTOR_RELATIVE prefix;
    NTSTATUS status = KiCopyFromUser(&prefix, userSd, 4);
    if (!NT_SUCCESS(status))
    {
        return status;
    }
    /* The revision is checked, as the named oracle function checks it
     * (third_party/wine dlls/ntdll/sec.c RtlValidSecurityDescriptor:
     * `sd->Revision == SECURITY_DESCRIPTOR_REVISION`). It was never looked
     * at, so a descriptor of any revision -- including one whose layout this
     * code has no idea how to read -- was parsed as if it were revision 1
     * (docs/review-2026-07 §9). SECURITY_DESCRIPTOR_REVISION was already
     * generated in abi/. */
    if (prefix.Revision != SECURITY_DESCRIPTOR_REVISION)
    {
        return STATUS_UNKNOWN_REVISION;
    }
    memset(parts, 0, sizeof(*parts));
    parts->control = prefix.Control;

    if (prefix.Control & SE_SELF_RELATIVE)
    {
        SECURITY_DESCRIPTOR_RELATIVE relative;
        status = KiCopyFromUser(&relative, userSd, sizeof(relative));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        const BYTE *base = userSd;
        if (relative.Owner != 0)
        {
            parts->owner = base + relative.Owner;
        }
        if (relative.Group != 0)
        {
            parts->group = base + relative.Group;
        }
        if ((relative.Control & SE_SACL_PRESENT) && relative.Sacl != 0)
        {
            parts->sacl = base + relative.Sacl;
        }
        if ((relative.Control & SE_DACL_PRESENT) && relative.Dacl != 0)
        {
            parts->dacl = base + relative.Dacl;
        }
    }
    else
    {
        SECURITY_DESCRIPTOR absolute;
        status = KiCopyFromUser(&absolute, userSd, sizeof(absolute));
        if (!NT_SUCCESS(status))
        {
            return status;
        }
        parts->owner = absolute.Owner;
        parts->group = absolute.Group;
        if (absolute.Control & SE_SACL_PRESENT)
        {
            parts->sacl = absolute.Sacl;
        }
        if (absolute.Control & SE_DACL_PRESENT)
        {
            parts->dacl = absolute.Dacl;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS SepCaptureSecurityDescriptor(PSECURITY_DESCRIPTOR userSd,
                                      PSEP_SECURITY_DESCRIPTOR *captured)
{
    SEP_SD_PARTS parts;
    NTSTATUS status = SepResolveSdParts(userSd, &parts);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* Measure pass. */
    ULONG ownerLength = 0, groupLength = 0, saclLength = 0, daclLength = 0;
    if (parts.owner != 0 && !NT_SUCCESS(status = SepCaptureSid(parts.owner, 0, &ownerLength, 0)))
    {
        return status;
    }
    if (parts.group != 0 && !NT_SUCCESS(status = SepCaptureSid(parts.group, 0, &groupLength, 0)))
    {
        return status;
    }
    if (parts.sacl != 0 && !NT_SUCCESS(status = SepCaptureAcl(parts.sacl, 0, &saclLength, 0)))
    {
        return status;
    }
    if (parts.dacl != 0 && !NT_SUCCESS(status = SepCaptureAcl(parts.dacl, 0, &daclLength, 0)))
    {
        return status;
    }

    PSEP_SECURITY_DESCRIPTOR blob =
        MiAllocatePool(sizeof(*blob) + ownerLength + groupLength + saclLength + daclLength);
    if (blob == 0)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    blob->control = parts.control & ~SE_SELF_RELATIVE;
    blob->ownerLength = ownerLength;
    blob->groupLength = groupLength;
    blob->saclLength = saclLength;
    blob->daclLength = daclLength;

    /* Copy pass (validates ACL walks on the kernel copy). Each part is
     * capped at what the measure pass allocated for it, checked before its
     * copy runs -- a part that changed size between the passes means user
     * memory is being raced, and the refusal has to precede the write, not
     * follow all four of them. */
    BYTE *cursor = SepSdData(blob);
    if (parts.owner != 0 &&
        !NT_SUCCESS(status = SepCaptureSid(parts.owner, cursor, &ownerLength, blob->ownerLength)))
    {
        goto fail;
    }
    cursor += ownerLength;
    if (parts.group != 0 &&
        !NT_SUCCESS(status = SepCaptureSid(parts.group, cursor, &groupLength, blob->groupLength)))
    {
        goto fail;
    }
    cursor += groupLength;
    if (parts.sacl != 0 &&
        !NT_SUCCESS(status = SepCaptureAcl(parts.sacl, cursor, &saclLength, blob->saclLength)))
    {
        goto fail;
    }
    cursor += saclLength;
    if (parts.dacl != 0 &&
        !NT_SUCCESS(status = SepCaptureAcl(parts.dacl, cursor, &daclLength, blob->daclLength)))
    {
        goto fail;
    }

    *captured = blob;
    return STATUS_SUCCESS;

fail:
    MiFreePool(blob);
    return status;
}
