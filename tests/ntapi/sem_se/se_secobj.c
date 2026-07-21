/*
 * sem_se/se_secobj.c — NtQuerySecurityObject / NtSetSecurityObject on a
 * kernel object (a named event; file SDs are host-shaped on the oracle and
 * out of CUI-2 scope).
 *
 * Oracle: dlls/ntdll/unix/security.c (query synthesizes the self-relative
 * blob; an object with no stored SD yields the zeroed 20-byte header with
 * SE_SELF_RELATIVE; set with an owner/group info bit but no owner/group in
 * the SD is INVALID_SECURITY_DESCR; NULL SD is ACCESS_VIOLATION),
 * server/handle.c get/set_security_object (READ_CONTROL to query, WRITE_DAC
 * / WRITE_OWNER per info bit to set), server/object.c
 * set_sd_defaults_from_token (missing parts default from the process token:
 * owner <- token owner, group <- token primary group; an unnamed DACL keeps
 * the stored one, else the token's default DACL).
 */
#include "util.h"

static void init_attr(OBJECT_ATTRIBUTES *attr, UNICODE_STRING *name, const WCHAR *path, int chars)
{
    name->Buffer = (WCHAR *)path;
    name->Length = (USHORT)(chars * sizeof(WCHAR));
    name->MaximumLength = name->Length;
    memset(attr, 0, sizeof(*attr));
    attr->Length = sizeof(*attr);
    attr->ObjectName = name;
}

START_TEST(se_secobj)
{
    NTSTATUS status;
    HANDLE event = NULL;
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING name;
    BYTE buf[512], set_buf[256], acl_buf[128];
    SECURITY_DESCRIPTOR_RELATIVE *sd = (SECURITY_DESCRIPTOR_RELATIVE *)buf;
    ULONG retlen, at;
    sid_buf world, users, expect_owner;

    sid_world(&world);
    sid_domain_users(&users);
    ULONG owner_len = sid_domain_users(&expect_owner);

    static const WCHAR event_path[] = W("\\BaseNamedObjects\\sem_se_secobj");
    init_attr(&attr, &name, event_path, sizeof(event_path) / sizeof(WCHAR) - 1);
    status = NtCreateEvent(&event, EVENT_ALL_ACCESS | WRITE_DAC | WRITE_OWNER | READ_CONTROL, &attr,
                           NotificationEvent, FALSE);
    ok(status == STATUS_SUCCESS, "create event -> %08lx", (unsigned long)status);

    /* --- a fresh object has no SD: the zeroed self-relative header --------- */
    memset(buf, 0xcc, sizeof(buf));
    retlen = 0;
    status = NtQuerySecurityObject(
        event, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        buf, sizeof(buf), &retlen);
    ok(status == STATUS_SUCCESS, "query fresh -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(SECURITY_DESCRIPTOR_RELATIVE), "fresh retlen %lu", (unsigned long)retlen);
    ok(sd->Revision == SECURITY_DESCRIPTOR_REVISION, "fresh revision %u", sd->Revision);
    ok(sd->Control == SE_SELF_RELATIVE, "fresh control %04x", sd->Control);
    ok(sd->Owner == 0 && sd->Group == 0 && sd->Sacl == 0 && sd->Dacl == 0,
       "fresh offsets %lu/%lu/%lu/%lu", (unsigned long)sd->Owner, (unsigned long)sd->Group,
       (unsigned long)sd->Sacl, (unsigned long)sd->Dacl);

    /* a too-small buffer: BUFFER_TOO_SMALL, needed size out */
    retlen = 0;
    status = NtQuerySecurityObject(event, DACL_SECURITY_INFORMATION, buf,
                                   sizeof(SECURITY_DESCRIPTOR_RELATIVE) - 1, &retlen);
    ok(status == STATUS_BUFFER_TOO_SMALL, "short fresh query -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(SECURITY_DESCRIPTOR_RELATIVE), "short fresh retlen %lu",
       (unsigned long)retlen);

    /* --- argument/validation errors on set ---------------------------------- */
    status = NtSetSecurityObject(event, DACL_SECURITY_INFORMATION, NULL);
    ok(status == STATUS_ACCESS_VIOLATION, "set NULL -> %08lx", (unsigned long)status);

    /* OWNER info bit demanded, SD carries no owner */
    build_sd(set_buf, NULL, NULL, 0, NULL, 0);
    status = NtSetSecurityObject(event, OWNER_SECURITY_INFORMATION, set_buf);
    ok(status == STATUS_INVALID_SECURITY_DESCR, "ownerless set -> %08lx", (unsigned long)status);
    status = NtSetSecurityObject(event, GROUP_SECURITY_INFORMATION, set_buf);
    ok(status == STATUS_INVALID_SECURITY_DESCR, "groupless set -> %08lx", (unsigned long)status);

    /* --- set a DACL only: owner/group default from the process token -------- */
    at = sizeof(ACL);
    at += put_ace(acl_buf + at, ACCESS_ALLOWED_ACE_TYPE, 0, EVENT_ALL_ACCESS, world.buf);
    put_acl(acl_buf, at, 1);
    ULONG acl_len = at;
    build_sd(set_buf, NULL, NULL, 1, acl_buf, acl_len);
    status = NtSetSecurityObject(event, DACL_SECURITY_INFORMATION, set_buf);
    ok(status == STATUS_SUCCESS, "set DACL -> %08lx", (unsigned long)status);

    ULONG expected_len = sizeof(SECURITY_DESCRIPTOR_RELATIVE) + owner_len + owner_len + acl_len;
    memset(buf, 0xcc, sizeof(buf));
    retlen = 0;
    status = NtQuerySecurityObject(
        event, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        buf, sizeof(buf), &retlen);
    ok(status == STATUS_SUCCESS, "query after set -> %08lx", (unsigned long)status);
    ok(retlen == expected_len, "retlen %lu, expected %lu", (unsigned long)retlen,
       (unsigned long)expected_len);
    ok((sd->Control & SE_SELF_RELATIVE) && (sd->Control & SE_DACL_PRESENT), "control %04x",
       sd->Control);
    /* parts are emitted in owner, group, sacl, dacl order right after the header */
    ok(sd->Owner == sizeof(*sd), "owner offset %lu", (unsigned long)sd->Owner);
    ok(equal_sid(buf + sd->Owner, expect_owner.buf), "defaulted owner not the token owner");
    ok(sd->Group == sd->Owner + owner_len, "group offset %lu", (unsigned long)sd->Group);
    ok(equal_sid(buf + sd->Group, expect_owner.buf), "defaulted group not the primary group");
    ok(sd->Sacl == 0, "sacl offset %lu", (unsigned long)sd->Sacl);
    ok(sd->Dacl == sd->Group + owner_len, "dacl offset %lu", (unsigned long)sd->Dacl);
    ok(memcmp(buf + sd->Dacl, acl_buf, acl_len) == 0, "stored DACL mismatch");

    /* --- info-bit filtering: a DACL-only query omits owner and group --------- */
    memset(buf, 0xcc, sizeof(buf));
    retlen = 0;
    status = NtQuerySecurityObject(event, DACL_SECURITY_INFORMATION, buf, sizeof(buf), &retlen);
    ok(status == STATUS_SUCCESS, "dacl-only query -> %08lx", (unsigned long)status);
    ok(retlen == sizeof(*sd) + acl_len, "dacl-only retlen %lu", (unsigned long)retlen);
    ok(sd->Owner == 0 && sd->Group == 0, "dacl-only owner/group %lu/%lu", (unsigned long)sd->Owner,
       (unsigned long)sd->Group);
    ok(sd->Dacl == sizeof(*sd), "dacl-only dacl offset %lu", (unsigned long)sd->Dacl);

    /* --- set an explicit owner; the DACL and group survive -------------------- */
    build_sd(set_buf, world.buf, NULL, 0, NULL, 0);
    status = NtSetSecurityObject(event, OWNER_SECURITY_INFORMATION, set_buf);
    ok(status == STATUS_SUCCESS, "set owner -> %08lx", (unsigned long)status);

    memset(buf, 0xcc, sizeof(buf));
    status = NtQuerySecurityObject(
        event, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        buf, sizeof(buf), &retlen);
    ok(status == STATUS_SUCCESS, "query after owner set -> %08lx", (unsigned long)status);
    ok(sd->Owner && equal_sid(buf + sd->Owner, world.buf), "owner not updated");
    ok(sd->Group && equal_sid(buf + sd->Group, expect_owner.buf), "group lost on owner set");
    ok(sd->Dacl && memcmp(buf + sd->Dacl, acl_buf, acl_len) == 0, "DACL lost on owner set");

    /* --- access enforcement ----------------------------------------------------
     * query wants READ_CONTROL; setting a DACL wants WRITE_DAC; setting the
     * owner wants WRITE_OWNER. An EVENT_MODIFY_STATE-only handle has none. */
    HANDLE narrow = NULL;
    static const WCHAR narrow_path[] = W("\\BaseNamedObjects\\sem_se_secobj");
    init_attr(&attr, &name, narrow_path, sizeof(narrow_path) / sizeof(WCHAR) - 1);
    status = NtOpenEvent(&narrow, EVENT_MODIFY_STATE, &attr);
    ok(status == STATUS_SUCCESS, "open narrow -> %08lx", (unsigned long)status);

    status = NtQuerySecurityObject(narrow, DACL_SECURITY_INFORMATION, buf, sizeof(buf), &retlen);
    ok(status == STATUS_ACCESS_DENIED, "query without READ_CONTROL -> %08lx",
       (unsigned long)status);

    build_sd(set_buf, NULL, NULL, 1, acl_buf, acl_len);
    status = NtSetSecurityObject(narrow, DACL_SECURITY_INFORMATION, set_buf);
    ok(status == STATUS_ACCESS_DENIED, "set DACL without WRITE_DAC -> %08lx",
       (unsigned long)status);

    build_sd(set_buf, world.buf, NULL, 0, NULL, 0);
    status = NtSetSecurityObject(narrow, OWNER_SECURITY_INFORMATION, set_buf);
    ok(status == STATUS_ACCESS_DENIED, "set owner without WRITE_OWNER -> %08lx",
       (unsigned long)status);

    NtClose(narrow);
    NtClose(event);
}
