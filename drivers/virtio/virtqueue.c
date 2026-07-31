/* drivers/virtio/virtqueue.c — one polled split virtqueue (see virtio.h).
 *
 * Spec: virtio 1.2 cs01 §2.7 (split virtqueues), §2.7.13 (supplying
 * buffers + barriers), §2.7.14 (receiving used buffers). Polling only —
 * no interrupts, no VIRTQ_AVAIL_F_NO_INTERRUPT games; we always notify
 * and always poll (Art. 3: the simplest correct thing).
 */
#include "drivers/virtio/virtio.h"
#include "kernel/mm/phys.h"
#include "kernel/mm/pool.h"
#include "kernel/lib/string.h"
#include "kernel/init/panic.h"

/* Full barrier: the spec's "suitable memory barrier" (§2.7.13.3.1). On
 * x86-64 this compiles to mfence; it also stops compiler reordering. */
static inline void VioMemoryBarrier(void)
{
    __sync_synchronize();
}

int VioInitializeVirtqueue(VIO_VIRTQUEUE *queue, uint16_t queueIndex, uint16_t queueSize)
{
    if (queueSize == 0)
    {
        return 0;
    }
    if (queueSize > 256)
    {
        /* One frame per area caps the ring: 16*256 = 4096 descriptor bytes,
         * avail 6+2*256 = 518, used 6+8*256 = 2054 (§2.7 area sizes). The
         * driver MAY configure a smaller power-of-2 size (§4.1.4.3.2). */
        queueSize = 256;
    }

    queue->queueIndex = queueIndex;
    queue->queueSize = queueSize;
    queue->lastUsedIdx = 0;
    queue->freeHead = 0;

    queue->descPhysical = MiAllocatePage();
    queue->availPhysical = MiAllocatePage();
    queue->usedPhysical = MiAllocatePage();
    if (queue->descPhysical == 0 || queue->availPhysical == 0 || queue->usedPhysical == 0)
    {
        /* Give back whatever DID come out of the allocator. A partial
         * failure used to leak every frame it had already taken
         * (docs/review-2026-07 §7). */
        if (queue->descPhysical != 0)
        {
            MiFreePage(queue->descPhysical);
        }
        if (queue->availPhysical != 0)
        {
            MiFreePage(queue->availPhysical);
        }
        if (queue->usedPhysical != 0)
        {
            MiFreePage(queue->usedPhysical);
        }
        queue->descPhysical = 0;
        queue->availPhysical = 0;
        queue->usedPhysical = 0;
        return 0;
    }
    queue->desc = MiPhysicalToVirtual(queue->descPhysical);
    queue->avail = MiPhysicalToVirtual(queue->availPhysical);
    queue->used = MiPhysicalToVirtual(queue->usedPhysical);
    memset(queue->desc, 0, PAGE_SIZE);
    memset(queue->avail, 0, PAGE_SIZE);
    memset(queue->used, 0, PAGE_SIZE);

    /* Page-aligned areas exceed every §2.7.1 alignment requirement
     * (16 / 2 / 4). Chain all descriptors into the free list. */
    for (uint16_t i = 0; i < queueSize; i++)
    {
        queue->desc[i].next = (uint16_t)(i + 1);
    }
    return 1;
}

int VioSubmitAndPoll(VIO_VIRTQUEUE *queue, const VIO_SEGMENT *segments, int segmentCount)
{
    ASSERT(segmentCount > 0 && segmentCount <= queue->queueSize);

    /* Build the descriptor chain from the free list (§2.7.13.1). The driver
     * is fully synchronous, so the free list is always intact here. */
    uint16_t head = queue->freeHead;
    uint16_t index = head;
    for (int i = 0; i < segmentCount; i++)
    {
        VIRTQ_DESC *descriptor = &queue->desc[index];
        descriptor->addr = segments[i].physical;
        descriptor->len = segments[i].length;
        descriptor->flags = (uint16_t)((segments[i].deviceWrites ? VIRTQ_DESC_F_WRITE : 0) |
                                       (i + 1 < segmentCount ? VIRTQ_DESC_F_NEXT : 0));
        if (i + 1 < segmentCount)
        {
            index = descriptor->next; /* free-list order already chains them */
        }
        else
        {
            queue->freeHead = descriptor->next;
            descriptor->next = 0;
        }
    }

    /* Publish: ring entry, barrier, idx, barrier, notify (§2.7.13.2-.4;
     * the §2.7.13.3.1 barrier orders descriptor/ring stores before the idx
     * store the device polls). */
    queue->avail->ring[queue->avail->idx % queue->queueSize] = head;
    VioMemoryBarrier();
    queue->avail->idx++;
    VioMemoryBarrier();
    /* §4.1.5.2: write the 16-bit virtqueue index to the notify address. */
    *queue->notify = queue->queueIndex;

    /* Poll the used ring (§2.7.14). The device sets used elem len before
     * used->idx (§2.7.8.2), so idx-then-read with a barrier is safe. */
    for (uint64_t spins = 0; spins < 1000000000ULL; spins++)
    {
        if (queue->used->idx != queue->lastUsedIdx)
        {
            VioMemoryBarrier();
            VIRTQ_USED_ELEM *element = &queue->used->ring[queue->lastUsedIdx % queue->queueSize];
            queue->lastUsedIdx++;
            ASSERT(element->id == head);

            /* Return the chain to the free list. */
            uint16_t tail = head;
            int count = 1;
            while (count < segmentCount)
            {
                tail = queue->desc[tail].next;
                count++;
            }
            queue->desc[tail].next = queue->freeHead;
            queue->freeHead = head;
            return 1;
        }
        __asm__ volatile("pause");
    }
    return 0; /* device wedged; the caller panics loudly */
}

/* --- receive queues (see virtio.h) ----------------------------------------- */

void VioPostReceiveBuffer(VIO_VIRTQUEUE *queue, uint16_t descriptorIndex, uint64_t physical,
                          uint32_t length)
{
    ASSERT(descriptorIndex < queue->queueSize);

    /* A single device-writable descriptor, no chain (§2.7.5): one buffer,
     * one event. The slot belongs to the caller for the device's lifetime,
     * so it is written in place rather than taken from the free list. */
    VIRTQ_DESC *descriptor = &queue->desc[descriptorIndex];
    descriptor->addr = physical;
    descriptor->len = length;
    descriptor->flags = VIRTQ_DESC_F_WRITE;
    descriptor->next = 0;

    /* Publish: ring entry, barrier, idx (§2.7.13.2-.3; the §2.7.13.3.1
     * barrier orders the descriptor and ring stores before the idx store
     * the device reads). */
    queue->avail->ring[queue->avail->idx % queue->queueSize] = descriptorIndex;
    VioMemoryBarrier();
    queue->avail->idx++;
}

void VioNotifyQueue(VIO_VIRTQUEUE *queue)
{
    /* Order the avail->idx store before the notify the device reacts to. */
    VioMemoryBarrier();
    /* §4.1.5.2: write the 16-bit virtqueue index to the notify address. */
    *queue->notify = queue->queueIndex;
}

int VioTryPopUsed(VIO_VIRTQUEUE *queue, uint16_t *idOut, uint32_t *lengthOut)
{
    if (queue->used->idx == queue->lastUsedIdx)
    {
        return 0;
    }
    /* The device writes the used element before advancing used->idx
     * (§2.7.8.2), so a barrier after observing the new idx orders our read
     * of the element after the read of idx that revealed it. */
    VioMemoryBarrier();
    VIRTQ_USED_ELEM *element = &queue->used->ring[queue->lastUsedIdx % queue->queueSize];
    *idOut = (uint16_t)element->id;
    *lengthOut = element->len;
    queue->lastUsedIdx++;
    return 1;
}
