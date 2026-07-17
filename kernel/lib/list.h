/* kernel/lib/list.h — NT doubly-linked circular list primitives (M2).
 *
 * These are the real NT names with the real NT signatures (declared in
 * third_party/wine/include/ddk/wdm.h); a LIST_ENTRY-based structure is how
 * every dispatcher wait list and queue in this kernel is threaded.
 */
#ifndef PROSKRNL_KERNEL_LIB_LIST_H
#define PROSKRNL_KERNEL_LIB_LIST_H

#include "abi/ntdef.h"
#include "kernel/init/panic.h"
#include <stddef.h>

#define CONTAINING_RECORD(address, type, field)                                                    \
    ((type *)((char *)(address) - offsetof(type, field)))

static inline void InitializeListHead(PLIST_ENTRY head)
{
    head->Flink = head;
    head->Blink = head;
}

static inline BOOLEAN IsListEmpty(const LIST_ENTRY *head)
{
    return head->Flink == head;
}

static inline void InsertTailList(PLIST_ENTRY head, PLIST_ENTRY entry)
{
    PLIST_ENTRY last = head->Blink;
    /* The head's links must agree with its neighbours (NT's checked-build
     * list corruption check) — catches scribbles and use-after-remove. */
    ASSERT(last->Flink == head && head->Flink->Blink == head);
    entry->Flink = head;
    entry->Blink = last;
    last->Flink = entry;
    head->Blink = entry;
}

static inline void InsertHeadList(PLIST_ENTRY head, PLIST_ENTRY entry)
{
    PLIST_ENTRY first = head->Flink;
    ASSERT(first->Blink == head && head->Blink->Flink == head);
    entry->Flink = first;
    entry->Blink = head;
    first->Blink = entry;
    head->Flink = entry;
}

/* Returns TRUE if the list became empty. */
static inline BOOLEAN RemoveEntryList(PLIST_ENTRY entry)
{
    PLIST_ENTRY previous = entry->Blink;
    PLIST_ENTRY next = entry->Flink;
    /* Both neighbours must still point at the entry — catches double-remove. */
    ASSERT(previous->Flink == entry && next->Blink == entry);
    previous->Flink = next;
    next->Blink = previous;
    return previous == next;
}

static inline PLIST_ENTRY RemoveHeadList(PLIST_ENTRY head)
{
    PLIST_ENTRY entry = head->Flink;
    ASSERT(!IsListEmpty(head));
    RemoveEntryList(entry);
    return entry;
}

#endif /* PROSKRNL_KERNEL_LIB_LIST_H */
