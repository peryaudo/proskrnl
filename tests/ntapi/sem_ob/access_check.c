/*
 * sem_ob/access_check.c — Ob create/open access checks (CUI-6).
 *
 * Retiring the always-allow shortcut: an object created with a security
 * descriptor is subject to a real DACL check at open time, and generic /
 * MAXIMUM_ALLOWED requests map through the type's GENERIC_MAPPING. Oracle
 * behaviour pinned from the pinned tree (server/token.c check_object_access
 * / token_access_check; server/handle.c alloc_handle -> map_access):
 *
 *   - an object with NO security descriptor stays permissive — a specific
 *     request passes through and MAXIMUM_ALLOWED resolves to the type's
 *     full generic-all mask;
 *   - an object WITH a deny-DACL refuses the denied right (STATUS_ACCESS_
 *     DENIED) but grants an allowed one;
 *   - a zero desired access on open is STATUS_ACCESS_DENIED.
 */
#include "util.h"

NTSYSAPI NTSTATUS NTAPI NtQueryObject(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

#ifndef EVENT_QUERY_STATE
#define EVENT_QUERY_STATE 0x0001
#endif
#ifndef MAXIMUM_ALLOWED
#define MAXIMUM_ALLOWED 0x02000000
#endif

/* S-1-1-0 (World) — a group the boot token holds. */
static ULONG make_world(void *buf)
{
    SID_IDENTIFIER_AUTHORITY world = {{0, 0, 0, 0, 0, 1}};
    SID *sid = (SID *)buf;
    sid->Revision = 1;
    sid->SubAuthorityCount = 1;
    sid->IdentifierAuthority = world;
    sid->SubAuthority[0] = 0;
    return 8 + 4;
}

/* Build a self-relative SD with owner=group=World and a DACL of two ACEs:
 * deny World EVENT_MODIFY_STATE, then allow World EVENT_ALL_ACCESS. */
static ULONG build_deny_sd(BYTE *buf)
{
    /* Layout: SD | owner SID | group SID | ACL. */
    SECURITY_DESCRIPTOR_RELATIVE *sd = (SECURITY_DESCRIPTOR_RELATIVE *)buf;
    ULONG off = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
    memset(sd, 0, sizeof(*sd));
    sd->Revision = SECURITY_DESCRIPTOR_REVISION;
    sd->Control = SE_SELF_RELATIVE | SE_DACL_PRESENT;

    ULONG ownerOff = off;
    off += make_world(buf + off);
    ULONG groupOff = off;
    off += make_world(buf + off);

    ULONG daclOff = off;
    ACL *acl = (ACL *)(buf + daclOff);
    ULONG aclStart = off;
    off += sizeof(ACL);
    /* deny ACE: type(1) flags(0) size sidStart mask sid */
    for (int pass = 0; pass < 2; pass++)
    {
        BYTE *ace = buf + off;
        WORD sidLen = 12;
        WORD aceSize = (WORD)(4 + 4 + sidLen); /* header + mask + sid */
        ace[0] = pass == 0 ? 1 : 0;            /* DENIED / ALLOWED */
        ace[1] = 0;
        ace[2] = (BYTE)(aceSize & 0xff);
        ace[3] = (BYTE)(aceSize >> 8);
        ACCESS_MASK mask = pass == 0 ? EVENT_MODIFY_STATE : EVENT_ALL_ACCESS;
        memcpy(ace + 4, &mask, 4);
        make_world(ace + 8);
        off += aceSize;
    }
    acl->AclRevision = ACL_REVISION;
    acl->Sbz1 = 0;
    acl->AclSize = (WORD)(off - aclStart);
    acl->AceCount = 2;
    acl->Sbz2 = 0;

    sd->Owner = ownerOff;
    sd->Group = groupOff;
    sd->Dacl = daclOff;
    return off;
}

START_TEST(access_check)
{
    NTSTATUS status;
    HANDLE event = NULL, opened = NULL;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attr;

    /* --- no-SD object: MAXIMUM_ALLOWED resolves to the full mask ---------- */
    init_ustr(&name, W("\\BaseNamedObjects\\prsk_cui6_nosd_event"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtCreateEvent(&event, MAXIMUM_ALLOWED, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create no-sd -> %08lx", (unsigned long)status);
    {
        OBJECT_BASIC_INFORMATION obi;
        memset(&obi, 0, sizeof(obi));
        status = NtQueryObject(event, ObjectBasicInformation, &obi, sizeof(obi), NULL);
        ok(status == STATUS_SUCCESS, "query basic -> %08lx", (unsigned long)status);
        ok((obi.GrantedAccess & EVENT_ALL_ACCESS) == EVENT_ALL_ACCESS,
           "MAXIMUM_ALLOWED granted the full mask (%08lx)", (unsigned long)obi.GrantedAccess);
    }
    NtClose(event);
    event = NULL;

    /* --- SD object: deny-DACL refuses the denied right ------------------- */
    BYTE sdBuf[256];
    ULONG sdLen = build_deny_sd(sdBuf);
    (void)sdLen;
    init_ustr(&name, W("\\BaseNamedObjects\\prsk_cui6_sd_event"));
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    attr.SecurityDescriptor = sdBuf;
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS, &attr, NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create with sd -> %08lx", (unsigned long)status);

    /* Open the denied right -> ACCESS_DENIED. */
    init_attr(&attr, NULL, &name, OBJ_CASE_INSENSITIVE);
    status = NtOpenEvent(&opened, EVENT_MODIFY_STATE, &attr);
    ok(status == STATUS_ACCESS_DENIED, "open denied right -> %08lx", (unsigned long)status);

    /* Open an allowed right -> success. */
    opened = NULL;
    status = NtOpenEvent(&opened, EVENT_QUERY_STATE, &attr);
    ok(status == STATUS_SUCCESS, "open allowed right -> %08lx", (unsigned long)status);
    if (opened != NULL)
    {
        NtClose(opened);
    }

    /* Zero desired access -> ACCESS_DENIED. */
    opened = NULL;
    status = NtOpenEvent(&opened, 0, &attr);
    ok(status == STATUS_ACCESS_DENIED, "open zero access -> %08lx", (unsigned long)status);

    NtClose(event);
}
