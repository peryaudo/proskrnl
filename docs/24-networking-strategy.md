# 24 — Networking Strategy (virtio-net + lwIP + `\Device\Afd`)

Like `docs/19`, `docs/22` and `docs/23`, this document is **not** an argument for
amending Article 3 — the mandate list is closed, and nothing below is justified on
performance. Unlike `docs/23`, it is not an Article 2 amendment either: every entity
this design makes observable is NT-present — `\Device\Afd` is afd.sys's device on real
Windows, `\Device\Nsi` is nsiproxy.sys's, no new process appears, and the NIC itself
sits below the boundary where nothing ring-3 can see it. No hacks-ledger entry is
needed anywhere in this path.

The gate this document must argue instead is **`docs/11`'s**: lwIP would be only the
second third-party component ever linked into the GPL-2.0 kernel image, admitted under
the four conditions Flanterm established (permissive license; pinned unmodified
submodule of the official upstream; public API only, its source never reference
material; recorded in `docs/provenance.md`). §3 makes that argument; the admission
lands as **its own commit** — the submodule pin, the provenance entry, and the
amendment of `docs/11`'s "nothing but Flanterm does" sentence — before any networking
code, the way a mandate exit would. Refusing the admission is a legitimate outcome;
§3a prices the alternative honestly.

Everything past that gate is ordinary work: consumer-driven (Art. 5), spec-cited at
the device (G8), generated at the contract (G4), one authority per mechanism
(Art. 11), loud when unbuilt (G12), frontier-declared when it parks (G14).

---

## 1. What the contract actually is

The single most important measured fact: **Wine's PE ws2_32 crosses the NT boundary
purely through `Nt*` calls.** `dlls/ws2_32/socket.c` (pinned tree, Wine 11.13)
contains zero unixlib references — the entire socket data path is `NtOpenFile`,
`NtDeviceIoControlFile`, `NtClose` and ordinary waits. The kernel owes networking no
new syscall id and no new device name; it owes the **AFD ioctl dialect this ws2_32
speaks**, on a device NT already has.

### a. The socket lifecycle ws2_32 performs

- **Create is two steps**: `NtOpenFile` of exactly `\Device\Afd` (no trailing
  component, no EA buffer; `GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE`;
  `FILE_SYNCHRONOUS_IO_NONALERT` only when the caller did *not* ask for
  `WSA_FLAG_OVERLAPPED` — plain `socket()` sockets are **asynchronous handles**),
  then `IOCTL_AFD_WINE_CREATE` carrying `{family, type, protocol, flags}`. A handle
  is a socket only after the second step. The device swallows any trailing path —
  `\Device\Afd\foobar` opens successfully, and the pinned suite asserts it
  (`dlls/ws2_32/tests/afd.c`, `test_open_device`).
- **Two code families**, both issued through `NtDeviceIoControlFile`:
  the seven native-compatible codes (`IOCTL_AFD_BIND/LISTEN/RECV/POLL/GETSOCKNAME/
  EVENT_SELECT/GET_EVENTS`, `FILE_DEVICE_BEEP`-based like real afd.sys), and the
  Wine-private set `IOCTL_AFD_WINE_*` — `CTL_CODE(FILE_DEVICE_NETWORK, fn,
  METHOD_BUFFERED, FILE_ANY_ACCESS)` with function numbers running contiguously
  200…304 (`include/wine/afd.h:187-293`): create/accept/accept-into/connect/
  shutdown/recvmsg/sendmsg/transmit, the fcntl-ish verbs (FIONBIO, FIONREAD,
  SIOCATMARK, complete-async, defer, get-info), and **one distinct ioctl per socket
  option** (a get passes `optval` as the *output* buffer, a set as the *input*;
  `optlen` comes back through `io.Information`).
- **Readiness is three mechanisms over one 13-bit state**: `IOCTL_AFD_POLL`
  (`select`/`WSAPoll` — a caller-built socket array with per-socket in/out flag
  words, a timeout, and an `exclusive` variant that displaces a prior exclusive
  poll), `IOCTL_AFD_EVENT_SELECT` + `IOCTL_AFD_GET_EVENTS`
  (`WSAEventSelect`/`WSAEnumNetworkEvents` — a mask plus an event, then a
  flags-and-13-status-words readback), and `IOCTL_AFD_WINE_MESSAGE_SELECT`
  (`WSAAsyncSelect` — window-message posting; §5). The `AFD_POLL_*` bits and their
  Win32 `FD_*` mapping (`FD_CONNECT` ← `CONNECT|CONNECT_ERR`, `FD_CLOSE` ←
  `RESET|HUP`) are fixed in the header and in `socket.c`'s two mapping functions.
  One wire quirk is load-bearing and pinned by the suite: `GET_EVENTS` passes the
  event to reset **as the input-buffer pointer with length 0** (ntdll's own comment:
  `/* sic */`).
- **Completion is the docs/19 §1 contract, verbatim.** Synchronous ops pass a
  per-thread event and wait on it when the call answers `STATUS_PENDING`, then read
  `io.Status`. Overlapped ops cast the caller's `OVERLAPPED*` to the IOSB, and
  `WSAGetOverlappedResult` reads `Internal` with an acquire load — pairing with the
  IOSB-before-signal release ordering the department already implements — and, when
  the caller supplied no event, **waits on the socket handle itself**: socket file
  objects are waitable and signal on I/O completion, which
  `IopSignalRequestCompletion` already does for files. The APC and completion-port
  legs ride the same ioctl arguments as everywhere else; the low-bit-of-hEvent
  port-suppression convention applies unchanged.
- **`NtReadFile`/`NtWriteFile` must work on socket handles.** ws2_32 never issues
  them, but ntdll routes `ReadFile`/`WriteFile` on a socket into the recv/send path
  and the pinned suite tests it (`test_read_write`). **`NtClose` cancels pending
  socket I/O** (`test_async_cancel_on_handle_close`), as does thread termination for
  its thread's requests (`test_async_thread_termination`).

### b. Three columns collapse into one authority

Under Wine the surface is served by three cooperating parts: PE ws2_32, ntdll's unix
side (fd work: recv/send/sockopt against a host socket), and wineserver
(`server/sock.c`: the socket state machine — poll, event bits, accept queues,
nonblocking mode, the `STATUS_ALERTED` "now do the fd work yourself" round trip).
proskrnl's kernel replaces the second and third columns with **one** AFD device;
`STATUS_ALERTED` is seam-internal and never crosses the boundary, so the kernel
answers inline-or-`STATUS_PENDING` directly — the shape the caller was always
entitled to (`docs/19` §1.1).

**Provenance discipline, stated here because the temptation will recur:** the
*semantics* of that collapsed state machine (event-bit ordering, poll edge cases,
the FIONBIO/event-select interlock, accept-queue behavior) are pinned by
oracle-green tests — `tests/ntapi/sem_net/` and the ws2_32 winetest pairs — never by
transcribing `server/sock.c`. Kernel-code reference material remains Wine *headers*
and MS documentation (`docs/11`); `include/wine/afd.h` is a header and is the
generated contract's source, `server/sock.c` is LGPL implementation and is the
oracle's internals. We measure it from outside.

### c. What does not cross the NT boundary: name resolution

`getaddrinfo`/`gethostbyname`/`gethostbyaddr`/`gethostname`/`getnameinfo` are
ws2_32's **own five-entry unixlib** (`dlls/ws2_32/unixlib.c`) reached from
`protocol.c` — no device, no ioctl, no wineserver. On proskrnl that unixlib is
null-dispatched like every other, so resolution needs its own seam decision (§4f) —
a different seam from AFD, with the conhost/mmdevapi recipe already waiting for it.

### d. The adjacent surface: NSI

iphlpapi (`GetAdaptersAddresses` and kin) is a pure client of nsi.dll, which opens
`\??\Nsi` → `\Device\Nsi` and issues five `IOCTL_NSIPROXY_WINE_*` codes
(`include/wine/nsi.h:419-425`): enumerate-all, get-all-parameters, get-parameter,
icmp-echo, change-notification. On Windows and on Wine alike the device belongs to
nsiproxy.sys — NT-present, so implementing a minimal `\Device\Nsi` is ordinary
Article 1 work, scoped to the tables real consumers read (§4e).

## 2. What exists today (measured)

- **ws2_32 is baked as dormant data** — it cannot load; `getaddrinfo` has glue
  stand-ins (`docs/03` "ws2_32"). No socket code, no `\Device\Afd`, no lwIP exists
  anywhere in the tree; every reference is forward-looking prose.
- **The pending engine expects exactly this consumer.** `kernel/io/io.h:375-379`:
  *"A future genuinely pended DATA transfer (Net-1's AFD is the expected consumer)
  grows THIS engine — buffer/length legs beside the IOSB — rather than a fourth
  bookkeeping shape."* CUI-8 delivered the data legs, the cross-context ownership
  convention (§5d there), `CancelPending`, and the single harvest authority
  `IoDrainDeviceCompletions` reached from the tick tail every millisecond — the
  guest-clocked 1 ms bound (`docs/19` §11c).
- **The Io device model is ready as-is**: `IoPublishDevice` + the `IO_VFS_OPS`
  table, `DeviceControl` fed by `NtDeviceIoControlFile` with both buffers bounced
  through pool, `IopPrepareCompletionApc` allocated *before* the verb so completion
  cannot fail, and condrv as the ioctl-heavy precedent (per-open state in
  `file->fsContext`, a wire-protocol header beside the driver).
- **The DMA floor is one page.** There is no contiguous allocator; every DMA buffer
  in the tree is a single frame, and `VioSubmitChain` takes per-segment physicals.
  An Ethernet frame (12-byte virtio-net header + 1514 bytes) fits a frame with room
  to spare. Virtio BAR mapping must happen inside `IoInitializeTransport`, before
  `MiFreezeKernelPml4` — stated three times in-tree; the net probe joins blk and
  input there.
- **The pinned QEMU (10.0.2) ships the device but not the backend.** `virtio-net-pci`
  is present; **slirp is not built** (`-netdev help` lists no `user` — libslirp was
  absent at configure time, the option is `auto`). The slirp source and the
  `filter-dump` pcap object are both in the build tree, so the purchase is an apt
  package plus a configure flag plus the `fetch_third_party` cache-key bump — the
  `--enable-gtk` / `--with-pulse` precedent, third instance (§6c).
- **The conformance suite pre-exists and is large**: `dlls/ws2_32/tests/afd.c`
  (2,962 lines — raw `NtDeviceIoControlFile` against `\Device\Afd`, the direct
  boundary test), `sock.c` (15,070 lines, 77 test functions), `protocol.c` (the
  resolver layer). No ws2_32 pair is in either winetest manifest today.
- **The prerequisites hold**: CUI-1's RTC (the TLS conviction is armed — `docs/22`)
  and CUI-8's overlapping I/O (an AFD `accept`/`recv` may never complete; the
  polled-synchronous model deadlocks by construction — `docs/19` §4).

## 3. Why lwIP

### a. Why not the hand-written "deliberately dumb" stack

The `docs/02` sketch predates this document. Four reasons it loses to adoption:

1. **The wire has no oracle.** Our entire verification apparatus — differential
   tests, the fuzzer, the winetest gate — observes the *syscall boundary*. TCP's
   hard parts (retransmission, reassembly, zero-window probing, simultaneous close,
   RST handling) are *wire* behavior: a home-grown stack that is wrong there passes
   every boundary test against loopback and fails only when a real peer with real
   loss arrives — the exact "correct-but-unconvictable" shape Article 6 exists to
   forbid, and no test we can write closes it. lwIP's protocol engine has been
   convicted by two decades of deployment against real peers; that is a form of
   verification we cannot manufacture.
2. **The provenance trap** (`docs/11` trap 1, called out for exactly this): TCP
   implementations in LLM training data are overwhelmingly Linux/BSD. Asking a model
   to "write TCP" is the laundering risk in its purest form. A pinned, unmodified,
   BSD-licensed submodule used through its public API has a provenance of one sha.
3. **Size and failure mode**: mature lwIP core (IPv4/6, TCP, UDP, DHCP, DNS, ARP,
   ICMP) is ~20k lines we neither write nor debug. The hand-written alternative is
   the project's known worst failure mode — an LLM writing plausible protocol code
   whose bugs are invisible to the harness (`docs/12`).
4. **lwIP already is the "deliberately dumb" stack.** Correctness-focused,
   single-threaded, no performance machinery of ours on top — Article 3's posture,
   implemented by someone else. We add no optimization to it (§5).

### b. The `docs/11` four-condition checklist

- **License**: lwIP is BSD-licensed (modified-BSD/3-clause; exact text re-verified
  at the pin commit) — permissive and GPL-2.0-compatible. ✓
- **Pinned unmodified submodule of the official upstream**
  (`git.savannah.nongnu.org/lwip.git`): the *port* — `lwipopts.h`, `arch/cc.h`, the
  `sys_now` shim — is lwIP's documented user-supplied configuration surface, not a
  patch; it lives in `drivers/net/`, and the submodule carries zero local commits. ✓
- **Public API only**: `netif_add`, `pbuf_*`, the raw `tcp_*`/`udp_*` callback API,
  `dhcp_start`, `sys_check_timeouts`. Its internals are not reference material for
  our code — the AFD layer above it is written against the *oracle*, not against
  lwIP's sources. ✓
- **`docs/provenance.md` entry** with the license named, in the adoption commit. ✓

### c. The design fit: `NO_SYS` mainloop mode is Article 3's machine

lwIP's `NO_SYS=1` mode — no OS abstraction, no threads, no mailboxes, a raw
callback API driven from one context plus `sys_check_timeouts()` — is precisely the
machine the constitution mandates: uniprocessor, one dispatcher lock, no kernel
preemption. Nothing must be invented to make lwIP single-threaded here; the kernel
already is (§4b states the invariant and where it is asserted). Configuration is as
much about what is turned **off**: the sockets and netconn APIs are not compiled;
`MEM_LIBC_MALLOC=0` with all pools **static** (sized at build, in kernel .bss), so
networking never enters `MiAllocatePool` on the rx path and the drain-context
allocator prohibition (docs/20 R2) is untouched by construction — lwIP exhaustion
is a counted, loud packet drop, never a kernel OOM; all checksums are computed and
verified in software, because no offload is negotiated (§4a).

### d. Why virtio-net

The same argument as blk and snd, and the cheapest section of the document: it rides
the modern virtio-pci transport, capability walker, and virtqueue code the tree
already runs; its spec is public (virtio 1.2 §5.1, device id 1) so provenance is
clean; and every constant lands under G8 citing the spec section, cross-checked
against the pinned QEMU device model (`hw/net/virtio-net.c`). The QEMU alternatives
(e1000/e1000e — a register-level Intel NIC emulation whose spec surface dwarfs the
feature) lose the same way intel-hda lost in `docs/23` §3.

## 4. Design

The stack has four layers, each with one authority, from the wire up:

```
 drivers/virtio/net.c      the device: rings, buffers, harvest      (§4a)
 drivers/net/              lwIP port + the netd mainloop thread     (§4b)
 drivers/afd.c             \Device\Afd: the ws2_32 boundary         (§4c)
 user/wine/dlls/wsresolv/  the resolver behind the ws2_32 seam      (§4f)
```

### a. `drivers/virtio/net.c` — the device

Modern virtio-pci only, like blk and input. Feature negotiation is minimal and
deliberate: `VIRTIO_NET_F_MAC` (read the address from device config — the device's
claim, never invented) plus `VERSION_1`; **not** negotiated: the checksum/TSO/GSO
offload family (correctness only — lwIP computes and verifies in software),
`MRG_RXBUF` (a full frame fits one page; multi-buffer receive buys nothing here),
`CTRL_VQ`, multiqueue, `EVENT_IDX` (the docs/19 §11c posture: the device may notify
per completion; we build no coalescing we cannot convict a need for).

Two virtqueues. **rx**: one page per buffer, allocated at probe time (pre-freeze,
inside `IoInitializeTransport` — only the BAR map and ring/buffer allocation happen
there; §4b's bring-up is later), all posted before `DRIVER_OK`. **tx**: a fixed set
of single-page bounce slots; the transmit path copies the pbuf chain into a slot
(lwIP's static pools live in kernel .bss and owe no physical contiguity — the copy
is the simplest correct thing, and blk's sector API set the precedent).

**No MSI-X vector.** `VioNetDrain` joins `IoDrainDeviceCompletions` (Art. 11 — the
one harvest authority) and is reached from the tick tail: a 1 ms guest-clocked
receive/completion bound, against TCP timers whose granularity is hundreds of
milliseconds. `docs/19` §11f is the controlling precedent — blk's interrupt was
convicted by idle-`hlt` and microsecond parks; a socket wake has no such consumer,
and the tick already runs unconditionally so no busy-poll arm comes back. The
escape is the same named one: a separate change against the same drain seam, if a
latency consumer ever convicts the millisecond. The added throughput ceiling is not
a contract term and is measured, not argued (§6e).

The drain is **harvest-store-wake and nothing more** (docs/20 R2): pop used rx
buffers, push their slot indices onto a fixed staged ring, pop completed tx slots
back to the free set, `KeSetEvent` the netd work event. No pbuf is allocated, no
byte is parsed, no lwIP function runs in drain context — protocol input is netd's
(§4b). If the staged ring is full the rx buffer is dropped and a counter ticks:
that is what a NIC under overload does, and the drop is loud in the `[KTEST]`
stats line (§6e).

### b. `drivers/net/` — the stack and its one thread

`third_party/lwip` (pinned) + the port layer: `lwipopts.h` (NO_SYS, static pools,
`LWIP_DHCP`, the loopback interface for `127.0.0.1`, dual-stack compiled from day
one — §5 stages the v6 *surface*), `arch/cc.h` over kernel primitives, `sys_now()`
from the tick count. Port files follow lwIP's own naming conventions, exempt from
`docs/15` the way tests are; everything of ours above them is NT-style.

**netd** — a kernel service thread, the lwIP mainloop: parks on the work event with
a timeout derived from lwIP's next-due timer; on wake it feeds staged rx frames to
`netif->input` (pbuf allocation happens here, in thread context, from lwIP's static
pools), services the loopback interface's queue, runs `sys_check_timeouts()`, and
transmits whatever the stack produced. Its park is a **new blocking point**: the
`tools/blocking_frontier.txt` entry lands in the same commit (G14), re-opening
docs/20 §8.4's checklist for it.

**The single-threading invariant, stated once and asserted:** lwIP is entered from
exactly two contexts — netd, and AFD verbs in syscall context — and never from the
drain or any interrupt path; no code path blocks while inside lwIP. Under Article
3's machine (no kernel preemption, uniprocessor) those two contexts therefore never
interleave inside the stack: the greppable "atomic under the no-preemption model"
justification, newest instance. A `NetInsideLwip` flag is asserted at every entry
seam. CUI-10's giant lock preserves the invariant verbatim — a thread holds the
lock for its whole kernel visit — and this paragraph is the row `docs/18` §5's
audit re-checks when that day comes.

**Configuration is DHCP, surfaced the NT way.** `dhcp_start` at bring-up (after the
boot volume mounts — bring-up is deliberately later than the pre-freeze probe);
when the lease binds, the kernel records it under
`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\<adapter>` in
the value names real Windows uses (`DhcpIPAddress`, `DhcpSubnetMask`,
`DhcpDefaultGateway`, `DhcpNameServer`, `DhcpServer` — MS-documented; G8 citation
at the writing site), rewritten on renewal. Nothing is baked: under slirp those
values arrive from the DHCP wire like anywhere else, and the resolver (§4f) reads
the registry rather than knowing an address. A static-configuration fallback knob
exists for test legs that want no DHCP dependency, off by default.

### c. `drivers/afd.c` — `\Device\Afd`

`IoPublishDevice(L"\\Device\\Afd", &AfdOps, ...)` beside condrv; `Create` accepts
and discards any trailing path (§1a, oracle-pinned); the socket state materializes
at `IOCTL_AFD_WINE_CREATE` into a per-open `AFD_SOCKET` hung off `file->fsContext`
(the `CONDRV_OPEN` precedent) wrapping one lwIP PCB. `DeviceControl` dispatches the
generated code table (§4d); every implemented verb's semantics are pinned by
`tests/ntapi/sem_net/` on the oracle first (G5), every unbuilt one refuses loudly
by name (G12) — with the *unknown-code* refusal shape itself pinned by the suite
(`test_unsupported_ioctls`), so even the default arm is oracle-shaped, and refusals
real callers depend on are the specific statuses the oracle answers, never
`STATUS_NOT_IMPLEMENTED`.

**Pending rides the CUI-8 engine unchanged.** `accept`, `recvmsg` on an empty
buffer, `connect`, `sendmsg` against a full send window, and `IOCTL_AFD_POLL` all
follow the same shape: resolve context at issue (the §5d ownership convention),
`IopPreparePendingRequest` with the data legs, return `STATUS_PENDING`; lwIP
callbacks running on netd complete them via `IopCompletePendingRequest` — IOSB
before signal, event/APC/port legs all inherited rather than rebuilt. Notably **the
kernel data path never parks a kernel thread on network progress**: ws2_32 waits in
ring 3 (§1a), so a socket that never completes wedges nothing. The one kernel-side
wait is the synchronous-handle case (`FILE_SYNCHRONOUS_IO_NONALERT` sockets, and
`NtReadFile`/`NtWriteFile` on them): that wait is cancellable (`IoWaitCancellable`,
the npfs shape) and is the second G14 frontier entry of the milestone.
`CancelPending` is implemented from day one — `NtClose` and thread termination both
cancel pended socket I/O, and the pinned suite tests both.

**The readiness state machine is kernel-owned**: the 13-bit `AFD_POLL_*` status per
socket, updated from lwIP callbacks; `POLL` parks against it (with the `exclusive`
displacement rule), `EVENT_SELECT`/`GET_EVENTS` latch it into the
event-plus-13-status-words shape, and the FIONBIO/event-select interlock
(`STATUS_INVALID_PARAMETER` when clearing nonblocking under an active mask) is
reproduced from the pin, not from reading the server. Socket file objects are
waitable and signal on completion via the existing `IopSignalRequestCompletion`
authority (§1a's `WSAGetOverlappedResult` leg).

**Buffering is ours, above lwIP**: a per-socket receive ring (allocated from pool
at create time, in syscall context — never in drain) that `MSG_PEEK`/`MSG_WAITALL`
operate on; TCP window backpressure by withholding `tcp_recved()` until the app
consumes; UDP datagram queue with drop-oldest-refused semantics per the pin; send
via `tcp_write` into lwIP's own buffer with the `sent` callback completing a parked
sender. The lwIP `err_t` → NTSTATUS table is small, total, and pinned — ws2_32's
own `NtStatusToWSAError` table names the statuses the kernel must produce
(`STATUS_DEVICE_NOT_READY` for would-block, `STATUS_CONNECTION_RESET`, and kin).

### d. `abi/afd.h` and `abi/nsi.h` — the generated contract

`tools/gen_abi.py` grows extraction from `include/wine/afd.h` and
`include/wine/nsi.h` (G4: both ioctl families as closed-form values, the
`AFD_POLL_*` bits, and the parameter-struct layouts with `static_assert`s mirroring
the headers' own `C_ASSERT`s — `afd_create_params` 16, `afd_get_events_params` 56,
`afd_recvmsg_params` 48, and the rest). No hand-typed code numbers anywhere in the
kernel; the dispatch table consumes the generated header. The wow64 variants
(`afd_poll_params_32` and kin) generate alongside — WOW64 is done and its ws2_32
issues the 32-bit shapes.

### e. `\Device\Nsi` — minimal, consumer-scoped

The five `IOCTL_NSIPROXY_WINE_*` codes, of which **two are built at first**:
enumerate-all and get-all-parameters for exactly the tables `GetAdaptersAddresses`
reads (the NDIS ifinfo and IP unicast-address tables), answered from lwIP netif
state — one authority, no second interface database. Get-parameter arrives when a
consumer convicts a key; icmp-echo and change-notification refuse loudly (§5). The
device exists because off-the-shelf tools call `GetAdaptersAddresses` on the way to
a fetch; it grows strictly by conviction.

### f. The resolver: the ws2_32 seam + `wsresolv`

The one fork surface of the milestone, conhost/mmdevapi-shaped (`docs/06`): a
commit on `proskrnl-target` giving `protocol.c`'s `WS_CALL` dispatch a proskrnl leg
— taken only when `__wine_unix_call_dispatcher` is NULL (level-1 runtime dormancy,
the same guard as every other seam) — that lazily `LdrLoadDll`s **`wsresolv.dll`**
and dispatches the five entries through its export table with the pinned parameter
structs. Under real Wine the dispatcher is non-NULL and the leg is dead bytes; the
pin-bump PR carries the hack-meter delta and the oracle-green proof.

`wsresolv` itself is superproject PE code (`user/wine/dlls/wsresolv/`, the
winevsnd.drv recipe): `getaddrinfo` = numeric fast paths + the `hosts` file + a
minimal DNS client (A/AAAA/CNAME) speaking over **ws2_32's own public UDP socket
API** — the recursion is safe because the socket path never re-enters the resolver
— against servers read from the `Tcpip\Parameters` registry values §4b wrote.
`gethostname` reads the computer name; `getnameinfo` serves the numeric direction
and refuses PTR loudly until a consumer convicts it; `gethostbyname/addr` are thin
wrappers the way ws2_32's own PE side already treats them. The
`drivers/etc/{hosts,services,protocol,networks}` files ride the image as mkimage
furniture — the PE-side database lookups (`getservbyname` and kin) already read
them without any seam.

## 5. What deliberately stays unbuilt

Named, per the `docs/22` §5 discipline:

- **No offloads, no `MRG_RXBUF`, no `CTRL_VQ`, no multiqueue, no `EVENT_IDX`** —
  §4a; each is a performance axis Article 3 refuses, and absence of negotiation is
  absence of code.
- **No MSI-X vector for net** — §4a; the tick tail is the bound, the escape is
  named.
- **No TCP urgent data.** lwIP implements none, so `MSG_OOB`, `SIOCATMARK`'s
  at-mark transitions and `AFD_POLL_OOB` cannot be served honestly: the surface
  refuses loudly, the affected winetest cases park with signatures, and the
  divergence is a recorded `docs/03` deviation justified against consumers (no
  baked tool uses urgent data — it barely exists outside test suites).
- **No `IOCTL_AFD_WINE_MESSAGE_SELECT`** (`WSAAsyncSelect`) at first: completing it
  means posting window messages through wineserver-lite's queues — a GUI-era
  cross-component consumer no CUI tool has. Refuses loudly; its pairs park.
- **No ICMP surface** (`IOCTL_NSIPROXY_WINE_ICMP_ECHO`, `IcmpSendEcho`, raw
  sockets): ping is nobody's dependency on the acceptance path. lwIP answers echo
  *requests* from the wire as a stack property; originating them waits for a
  consumer.
- **No NSI change-notification** — refuses loudly; `SIO_ADDRESS_LIST_CHANGE` on AFD
  *parks and never completes* on a static-address machine, which is the correct
  answer (no change ever occurs) and costs nothing under the pending engine.
- **The AF_INET6 surface is staged.** The stack compiles dual-stack from day one
  (§4b — re-sizing pools twice is the expensive path), but v6 socket creation
  refuses until its own `sem_net` pins exist; the v6-dependent winetest cases park
  until then. v4 is the acceptance path.
- **No schannel** — the `docs/02` scope note, recorded in `docs/03` at Net-3:
  acceptance uses bundled-TLS tools (python/curl ship OpenSSL); schannel's engine
  is GnuTLS behind a null-dispatched unixlib, while raw bcrypt works as-is
  (SymCrypt is vendored PE-side).
- **No performance work in or above lwIP, ever** — no window tuning, no Nagle
  games beyond the `TCP_NODELAY` the boundary exposes, no zero-copy. Policy above
  the boundary, correctness below it.

## 6. Testability

### a. `sem_net` over loopback: the deterministic pin

The oracle (pinned Wine on the Linux host) serves the whole §1 surface over host
loopback with no privileges and no external network — `tests/ntapi/sem_net/` pins
create/bind/connect/accept/send/recv, the readiness trio, sockopts, cancellation
and close semantics there, green on the oracle before the kernel implements (G5).
On proskrnl the same binaries run against lwIP's loopback interface: kernel-only,
no device, no slirp — semantics isolated from the wire. `dlls/ws2_32/tests/afd.c`
is the raw-boundary conformance anchor beyond our own suite.

### b. The device verdict: pcap is the screendump

The Net-1 leg proves the wire without AFD existing: QEMU gets
`-netdev user -device virtio-net-pci` plus a `filter-dump` object writing a host
pcap. The guest boots, DHCP binds (a `[KTEST] net dhcp` line carries the bound
address), and a kmt smoke test drives an in-kernel TCP echo against the harness
via the raw API. The harness then reads the pcap — the WAV/screendump analog — and
asserts *content*: our MAC in the Ethernet source, the DISCOVER/REQUEST exchange,
the echo payload bytes. Property-based, never byte-golden or timing-based: packet
timing and slirp's TCP choices are host-scheduling artifacts, the `docs/19` §11c
class of trap.

### c. Buying the backend: slirp, cache bump, netsmoke

`tools/setup_linux.sh` adds libslirp (and the configure flag pinning it **on**, not
auto — a silent no-slirp build must fail loudly at configure, not at the leg) with
the `fetch_third_party` cache-prefix bump; third instance of the oracle/harness
backend purchase (fonts, Xvfb/GTK, pulse). A **netsmoke** check in the runner
asserts the QEMU in use actually offers `-netdev user` before any net leg is
judged — the fontsmoke/audiosmoke lesson: an environment that silently lacks its
backend turns every pair into a false verdict.

### d. The winetest spine

`ws2_32:afd`, `ws2_32:sock`, `ws2_32:protocol` enter `tests/winetest/manifest.txt`
under the existing discipline (`docs/21`): every pair listed, red ones parked with
triage signatures, the active list gated in CI on both runners. `sock.c`'s in-file
ordering constraints (iocp last) come free — the gate runs whole pairs. The
Net-2 done-when is stated in manifest terms, so "sockets work" ends as a measured
pair count, not a feeling.

### e. The win is a verdict (the §8.4 rule, twice)

Two correct-but-inert shapes must be excluded by numbers, not inference:

- **Loopback-only truth**: an AFD+lwIP build exercised solely over loopback passes
  every semantic test with a dead driver. The slirp legs (§6b, §6f) are the
  external conviction; both halves are required, neither substitutes.
- **Inline-only truth**: a socket layer that never actually pends — completing
  everything from syncing waits — passes loopback semantics too. The `[KTEST] net`
  verdict line carries pended-completion counts alongside rx/tx frame counts,
  drops, retransmits and pool high-water marks — numbers against committed floors
  where a floor makes sense, recorded facts where it does not.

**The fuzzer gets the deterministic subset only.** Socket *control-plane* ops
(create/bind/sockname/sockopt/refusal shapes) are oracle-deterministic and join the
op model; data-path ops are not (ISNs, ports, timing) and are convicted by `sem_net`
and the pairs instead — stated here so the omission is a decision, not a gap.

### f. The acceptance: an off-the-shelf HTTPS fetch

The Net-3 leg: the harness serves HTTPS on host loopback (a test CA, its root
provisioned to the tool's bundled trust store); the guest runs an unmodified
bundled-TLS tool (python or curl) fetching through slirp's host alias; the verdict
is the fetched content's hash plus the tool's exit code. The certificate's
`notBefore` postdates the retired frozen-clock base date, so a machine still
answering fake time fails the handshake — the conviction `docs/02` promised.
slirp's own TCP shim sits in this path and only this path: nothing pinned rides it
(§6a/§6b are loopback and pcap), so its behavior can never shape a semantic
verdict.

### g. What has no oracle

The driver's internals and the netd machinery (like Fb0, like snd): kmt verdicts —
ring exhaustion recovery, the staged-queue drop counter, the frontier-declared
parks actually parking — plus §6b's pcap artifact. The AFD boundary above them has
the real oracle, which is the point of the layering.

## 7. Risks (honest)

- **The AFD surface is the mountain, and it is wide, not deep.** ~112 ioctl codes,
  a 13-bit readiness machine with three consumers, and 15k lines of pre-existing
  conformance tests that will find every corner. Mitigations: the generated
  dispatch table (no transcription errors), consumer-first ordering (the verbs
  python/curl actually issue land first; the long sockopt tail lands by triage),
  G12 loudness so an unbuilt verb is a named serial line rather than a mystery, and
  the parking discipline so red pairs are a worked frontier, not a wall.
- **NT↔lwIP impedance lives in our layer.** `SO_RCVBUF`/`SO_SNDBUF` reporting
  against lwIP's static sizing, `SO_LINGER`/abortive-RST close, `SO_REUSEADDR`
  versus `SO_EXCLUSIVEADDRUSE`, `FIONREAD` at message boundaries, accept-queue
  depth: each is a place where the oracle's answer and lwIP's natural answer can
  differ, and the AFD layer must author the NT answer. The compensation is that
  every one is boundary-observable and therefore pinnable (Art. 5) — unlike wire
  behavior, divergence here is convictable, and each authored answer cites its pin.
- **Static pool sizing is a cliff with a counter.** Fixed pbuf/PCB pools mean a
  hard concurrent-connection ceiling; under-sizing surfaces as loud drops and
  `WSAENOBUFS`-shaped refusals. The sizes are recorded facts in `lwipopts.h`
  (per-value rationale comments), the high-water marks ride the `[KTEST]` line, and
  re-sizing on conviction is a one-line change — never a dynamic allocator.
- **Throughput on a 1 ms harvest is bounded and unmeasured until built.** A full
  ring per tick is hundreds of megabits — far above the acceptance's needs — but
  the number is measured and recorded at Net-1, not argued; if a real consumer
  ever convicts it, the MSI-X escape is named (§4a) and is not this milestone.
- **The seam grows the hack meter** by one commit (the `WS_CALL` leg), level-1
  dormant, oracle-green proof on the pin bump — the smallest seam of any subsystem
  so far; `wsresolv` itself adds zero fork lines.
- **DNS is a real protocol client in PE glue.** ~500 lines of wire format with
  truncation/CNAME/multi-server corners; scoped to what `getaddrinfo` consumers
  need, tested against the harness's own DNS (slirp serves one), and behind the
  most replaceable seam in the design — if it proves nastier than budgeted, the
  fallback is scoping acceptance to hosts-file/numeric resolution while the client
  matures, without touching the kernel.
- **Provenance temptation.** The fastest way to "know" an AFD corner is to read
  `server/sock.c`; the discipline (§1b) is that corners are learned from the
  oracle's observable behavior. This is written down precisely because the
  temptation will be constant.

## 8. Build order (G13: one meaningful unit per commit)

Milestone boundaries (`docs/02`: Net-1 wire, Net-2 boundary, Net-3 resolution)
marked in brackets.

1. **The lwIP admission** — submodule pin, `docs/provenance.md` entry, the
   `docs/11` amendment naming lwIP beside Flanterm. Own commit, before any code.
2. **`abi/afd.h` + `abi/nsi.h` generation** (`/gen-abi` grows; static_asserts
   mirror the headers' C_ASSERTs). Own commit.
3. **Slirp + netsmoke** (§6c): setup_linux + cache bump + the runner check.
4. **`drivers/virtio/net.c`** — probe/rings/buffers pre-freeze, drain joining
   `IoDrainDeviceCompletions`, G8 citations throughout; kmt smoke (MAC read, a
   transmitted frame in the pcap).
5. **`drivers/net/` + netd** — port layer, mainloop, DHCP, the registry lease
   write, the frontier entry for netd's park; the `run.sh net` leg with the pcap
   and `[KTEST]` verdicts. **[Net-1 done]**
6. **`sem_net` pins on the oracle** (G5) — the first tranche: lifecycle, data
   path, readiness trio, cancellation, close-cancels, unknown-code refusal shape.
7. **`drivers/afd.c` core** — create/bind/connect/listen/accept/recv/send over
   loopback, pending on the CUI-8 engine, `CancelPending`, waitable handles, the
   sync-handle wait + its frontier entry. `sem_net` tranche 1 green on proskrnl.
8. **Readiness + the tail** — poll (+exclusive), event-select/get-events with the
   sic convention, FIONBIO interlock, `NtRead/WriteFile` on sockets, sockopt verbs
   by consumer/triage order; `ws2_32:afd` and `ws2_32:sock` enter the manifest,
   red pairs parked with signatures. **[Net-2 done when the manifest says so]**
9. **`\Device\Nsi` minimal** (§4e) — the two table verbs GetAdaptersAddresses
   needs, from lwIP netif state.
10. **The resolver** — the seam commit on `proskrnl-target` (+ pin bump with
    hack-meter delta and oracle-green proof), `wsresolv.dll`, the etc-files
    furniture; `ws2_32:protocol` triaged.
11. **The acceptance leg** (§6f) + the `docs/03` records (schannel scope, urgent
    data, staged v6, authored-impedance pins) + README status. **[Net-3 done:
    an off-the-shelf tool completes an HTTPS fetch over virtio-net]**

## 9. Relationship to the other documents

- **`docs/19`** — the whole design rides CUI-8: the pending engine and its §5d
  ownership convention (§4c here), the drain authority and the §11f no-vector
  precedent (§4a), the §11c host-clock trap (every timing honesty note in §6), and
  §4's argument for why none of this was buildable earlier.
- **`docs/20`** — two new frontier entries (netd's park, the sync-handle wait) and
  the R2 drain discipline §4a is shaped around; the §5 STILL-TRUE tables re-open
  for the new blocking points, as that document requires.
- **`docs/11`** — the second-ever third-party admission (§3b) and the provenance
  disciplines (§1b, §3a) this design leans on hardest.
- **`docs/22`** — the real clock the TLS conviction spends; `sys_now` rides the
  same tick the timekeeping work calibrated.
- **`docs/06`** — the seam levels and landing recipe for §4f; the
  backend-purchase lesson, third instance (§6c).
- **`docs/21`** — the manifest discipline that turns Net-2's "done" into a pair
  count.
- **`docs/18`** — §4b's single-threading invariant is written to survive the giant
  lock verbatim and is named there as an audit row when CUI-10 arrives.
- **`docs/02`** — the Networking path milestones (Net-1…Net-3) carry the contract;
  this document is the design. References to "Net-1" in older documents and in
  `kernel/io/io.h` predate the split and read as the path.
- **`docs/03`** — gains the Net-3 records: schannel scope, TCP urgent data, staged
  AF_INET6, and every authored impedance answer with its pin.
