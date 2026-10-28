# GoThread API Overview

A curated guide to the most important public types in
**github.com/hilli/gothread** — a pure-Go implementation of Thread 1.4.0.

> Not a full godoc dump — highlights key types, relationships, and signatures.

**Persistent numeric-key compatibility warning:** `platform.SettingsKeyBorderAgentID`
is corrected from the conflicting `0x000b` to canonical `0x0011`;
`platform.SettingsKeySRPECDSAKey` is canonical `0x000b`, matching
`common/settings`. No existing record is migrated, relocated, erased, or silently
regenerated. Backends that used the old public BorderAgent numeric alias require
an explicit owner-reviewed compatibility decision before enabling durable SRP.
Unrecognized/legacy data in the SRP slot fails validation closed, not "missing."
A recognizable key record cannot establish an unknown external record's origin
or universal backward compatibility. Other legacy platform aliases are unchanged.

## Package Dependency Graph

```
                     ┌──────────────────┐
                     │    instance      │  Central owner — wires everything
                     └──────┬───────────┘
                            │
         ┌──────────────────┼──────────────────┐
         ▼                  ▼                  ▼
   ┌──────────┐     ┌─────────────┐     ┌──────────┐
   │  radio   │     │  platform   │     │ thread/  │
   └────┬─────┘     └─────────────┘     └────┬─────┘
        ▼                                    ▼
   ┌──────────┐                        ┌──────────┐
   │  mac/    │◄───────────────────────│  net/    │
   └──────────┘                        └──────────┘

  radio → mac → thread → net → instance
```

## 1. Core Types — `instance`

### Config

```go
type Config struct {
    Alarm            platform.Alarm    // millisecond timer
    Entropy          platform.Entropy  // crypto random source
    Settings         platform.Settings // persistent storage
    Logger           platform.Logger   // platform logging
    Radio            radio.Radio       // IEEE 802.15.4 radio

    ParentPriority   uint8   // 0-3, Connectivity TLV Flags
    SEDBufferSize    uint16  // SED buffer size
    SEDDatagramCount uint8   // SED datagram count
}
```

### Instance

The central object — owns every Thread stack module, drives them via a
single-goroutine cooperative event loop.

```go
func New(config Config) *Instance

func (inst *Instance) Start() error          // launch event loop
func (inst *Instance) Stop()                 // shutdown and wait
func (inst *Instance) IfConfigUp() error     // enable MAC/mesh interface
func (inst *Instance) IfConfigDown() error   // disable interface
func (inst *Instance) ThreadStart() error    // enable Thread, start attach
func (inst *Instance) ThreadStop() error     // disable Thread, detach
func (inst *Instance) IsRunning() bool
func (inst *Instance) IsThreadRunning() bool
func (inst *Instance) PostTask(fn func())    // post work (any goroutine)
func (inst *Instance) Do(ctx context.Context, op func() error) error
func (inst *Instance) SendUDP(payload []byte, info ip6.MessageInfo) error // loop-only
func (inst *Instance) ScheduleTimer(delay time.Duration, fn func())
func (inst *Instance) SignalEvents(events Event)
```

**Typical startup:**

```go
plat := simulation.NewPlatform()
inst := instance.New(instance.Config{
    Alarm: plat.Alarm, Entropy: plat.Entropy,
    Settings: plat.Settings, Logger: plat.Logger, Radio: plat.Radio,
})
if err := inst.Start(); err != nil {
    return err
}
return inst.Do(ctx, func() error {
    if err := inst.IfConfigUp(); err != nil {
        return err
    }
    return inst.ThreadStart() // Begins attachment; does not mean attached yet.
})
```

`New` initializes the effective MAC extended address from the injected radio's
`GetIEEEEui64()` before constructing identity-dependent modules. This propagates
through MAC/SubMac to `Radio.SetExtendedAddress` and supplies the same identity
to SLAAC, DHCPv6, prefix delegation, and border routing. Both radio address
methods use canonical EUI-64 bytes, most significant byte first; hardware/wire
byte reversal belongs in the driver or frame encoder. The link-local IPv6 IID
uses Modified EUI-64, toggling the universal/local bit without changing the MAC
address.

Nil-radio instances keep their existing zero identity. There is currently no
configured/restored effective-MAC override in `Config`: changing `Mac` or the
radio filter after construction does not update identities already captured by
other modules. The existing persisted SLAAC privacy secret and Joiner ID
derivation are unchanged; no randomized MAC policy is introduced.

### External executor and native UDP

External adapters use **one** scheduling layer:

```go
err := inst.Do(ctx, func() error {
    return inst.SendUDP(payload, ip6.MessageInfo{
        SockAddr: localAddress, SockPort: localPort,
        PeerAddr: peerAddress, PeerPort: peerPort,
        HopLimit: 64,
    })
})
```

`Do` runs an operation on the current instance event loop and returns its
**exact** result. It shares the existing 256-entry task queue, with no worker
goroutines or second executor. Full admission returns `errors.ErrNoBufs`; nil
context/operation returns `errors.ErrInvalidArgs`; not-started, stopping,
stopped, or stale-generation work returns `errors.ErrInvalidState` when it did
not start. A pre-cancelled or queued operation whose cancellation wins returns
`context.Canceled`/`DeadlineExceeded` and **never executes later**. Cancelled
wrappers occupy their bounded queue slot until drained.

Once an operation starts, cancellation and `Stop` cannot retract it: `Do` waits
for its real return, even after the context deadline. This is not a native
timeout or rollback guarantee. Do not retry an uncertain accepted side effect.
Concurrent `Stop` calls share one shutdown barrier; pending `Do` operations are
released without executing and cannot run in a restarted generation. Started
operations complete before `Stop` returns. Existing stack state and ordinary
timers survive an event-loop restart; `Stop` does not undo previously accepted
datagrams or perform `ThreadStop`/`IfConfigDown`. Partial/queued **fragmented**
datagrams and reassembly state are discarded on Stop; already prepared radio
frames cannot be retracted. Use ThreadStop/IfConfigDown via `Do` for interface
teardown and flushing of all traffic.

Call `Do`, `Start`, and `Stop` only **outside** loop callbacks. Inside the loop,
call loop-only stack methods directly. Never wrap `PostTask` in a helper
goroutine or call `Do` recursively. Legacy `PostTask`/`ScheduleTimer` remain
fire-and-forget and can block on their full queue; they are not substitutes for
cancellable admission. The MAC tasklet is coalesced separately through the
existing timer scheduler so it cannot block its own full external task queue.

`SendUDP` is loop-only and uses the existing secured forwarding/MAC pipeline,
not `UDPManager.HandleMessage` (which is ingress/local socket delivery).
It requires a running instance, enabled interface/MAC/forwarder, attached Thread
role, valid local radio identity and MAC security material. Source address and
both nonzero ports must be explicit. Sources are the current link-local/RLOC
identity or a `Valid` address on `Netif`; supported unicast source scopes are
link-local, ULA, and global `2000::/3`. Link-local and non-link-local source/peer
scopes cannot be mixed.

The existing direct routes are **valid rx-on-when-idle neighbors**,
including an established parent: canonical EUI-64-derived link-local peers, or
RLOC peers with the current mesh-local prefix. Existing direct LL/RLOC delivery
is unchanged by the narrower additional MTD gate below. Unknown LL destinations,
self-delivery, anycast, sleepy children and general FTD routing/EID resolution
still return `errors.ErrNoRoute`. Multicast/group/discovery, including mDNS, is not
implemented by this boundary. It returns `errors.ErrNotCapable` rather than
silently converting unsupported unicast to a MAC broadcast.

HopLimit zero defaults to 64; explicit 1-255 values are honored. `Ecn`,
`MulticastLoop`, `IsHostInterface`, `AllowZeroHopLimit`, and `LinkInfo` must all
remain zero/nil, otherwise admission returns `errors.ErrNotCapable`.
The shared framer computes and includes the IPv6 UDP checksum. The IPv6 link
MTU is **1280 uncompressed bytes**, permitting UDP application payload up to
**1232 bytes**. Larger payloads return `errors.ErrNoBufs` before admission.
Empty/small datagrams remain unfragmented; larger supported direct datagrams use
standard RFC 4944/RFC 6282 fragmentation owned by the stack, not application
chunks. Actual compressed headers, MAC addresses, security/MIC, and FCS determine
each frame budget. At ports 5540 and hops 1/64/255, the unfragmented thresholds
remain 85 app bytes for canonical link-local peers and 53 for fully inline
mesh-local addresses; crossing them no longer refuses an otherwise valid
MTU-sized datagram.

Success means **copied into the real bounded forwarding queue with MAC work
requested**, not TX complete, peer receipt, or Matter MRP ACK. Payload and retained
metadata are stack-owned before success; the caller can immediately reuse its
input. Missing forwarders return `errors.ErrInvalidState`, disabled forwarders
return `mesh.ErrForwarderDisabled`, and queue saturation returns the existing
`mesh.ErrQueueFull`. Latched persistence failures retain their `errors.Is`
identity. Later build/encryption/counter/radio errors remain asynchronous and
observable through drop/MAC counters, logs, and persistence latches. Do not wait
for a radio callback on its own event loop.

Use `Do` for UDP `Open`/`Bind`/`Close` and stack observations too. UDP receive
callbacks borrow payload, `MessageInfo`, and `LinkInfo` for their synchronous
duration. Copy retained data into an **application-owned bounded queue** without
blocking, and perform reads/PASE processing outside the loop. Close the UDP
socket through `Do` before closing/discarding that application queue; already
copied packets remain application-owned. This API adds no unbounded receive
worker, sockets, host-interface guessing, or local reinjection.

### Minimal always-on MTD parent-unicast handoff

The public API remains `Do` plus loop-only `SendUDP`. For a supported non-link-local
unicast final destination that is not already an existing direct route, an
**attached Child with MinimalThreadDevice (FTD bit clear) and RxOnWhenIdle**
can hand a datagram to its **established valid awake FTD/router parent**.
The actual MAC receiver mode must also be on. MLE, Instance, and MAC child RLOC
must agree, be a canonical child RLOC, and belong to that parent's canonical
router RLOC. The local and parent EUI-64 identities must be usable distinct
unicast identities; the current PAN cannot be broadcast and the mesh prefix
must be a configured ULA. A router, leader, FTD child, sleepy/ICD MTD, absent/
invalid/restoring/lost/sleepy parent, mismatched RLOC, or unusable identity cannot
gain this fallback.

The parent is selected as the **link-layer next hop**, not the logical IPv6
peer. Original explicit source, final `PeerAddr`, ports, hop, payload, IPv6/UDP
lengths/checksum, and standard fragmentation are preserved. No endpoint mesh
header or general EID query/pending-resolution mechanism is introduced.
The implementation reference is pinned
[OpenThread `7009584dadc20cf20c20a6062f357dd572ba6885`, `MeshForwarder::UpdateIp6Route`](https://github.com/openthread/openthread/blob/7009584dadc20cf20c20a6062f357dd572ba6885/src/core/thread/mesh_forwarder.cpp):
after disabled/detached, multicast, LL and FTD branches, the MTD path selects
the parent RLOC as MAC destination while preserving the original IP packet.
This API intentionally supports only the attached always-on unicast subset.

Sources remain actual valid assignments; no source is generated or inferred.
For a final peer outside the mesh-local prefix, the source must be an explicit
Valid Netif ULA/global assignment **outside** that mesh prefix, with nonzero
valid prefix-length metadata, global scope, and neither MeshLocal nor RLOC flag.
A mesh-local RLOC/EID is not accepted as an off-mesh-routable source. Nil/default,
unspecified, loopback, multicast, IPv4-mapped, unassigned/invalid and mixed-LL
source shapes retain their explicit errors.

**This is qualified local parent HANDOFF, not end-to-end route success.**
Netif assignment/prefix metadata cannot prove a border-router advertisement,
external reachability, source registration, or remote return route. The caller
must provision and verify the source's actual routability (for example a valid
OMR/global assignment) and the parent/upstream path; any ULA by itself proves
none of those. This library does not fabricate OMR addresses, discovery, network
data, routing advertisements, or success at the final peer. It also never
reinjects the packet through UDP ingress.

Admission snapshots the eligible parent, local RLOC/EUI/PAN/prefix and network
key. A bounded admission-owned validator rechecks those prerequisites and the
current source assignment **before each distinct fragment/counter** and before
delayed CSMA/software-retry radio attempts. It uses loop-owned SubMac state
without re-entering the upper MAC mutex. Parent loss/replacement, role/mode,
source invalidation, network/PAN or local identity change retires the remaining
owned datagram with the normal logged drop/resource-release path; no automatic
retargeting or extra source/address creation occurs. Key-sequence rotation with
the same network key retains normal per-frame reservations and exact MAC retry
semantics. A frame already accepted by a radio cannot be retracted; later
forwarding/delivery is not guaranteed by local acceptance.

MTU1280/UDP1232, shared count/byte/fragment/reassembly limits, SubmissionID
origin rules, `errors.Is`, nil/acceptance versus asynchronous completion, and
all executor cancellation/Stop guarantees remain unchanged. No general FTD
routing, multicast/group/mDNS/SRP/discovery, commissioning, sleepy/ICD, Wi-Fi/BLE,
native radio/storage geometry, or external consumer dependency is changed.

### Standard direct-neighbor fragmentation

The existing `Do`/`SendUDP` API is unchanged. The standards references are
[RFC 4944 section 5.3](https://www.rfc-editor.org/rfc/rfc4944#section-5.3) and
[RFC 6282 section 2](https://www.rfc-editor.org/rfc/rfc6282#section-2).
`datagram_size` and `datagram_offset` describe **original IPv6 bytes**, never a
compressed buffer's length. FRAG1 carries the compressed headers and first data
range; FRAGN carries original bytes at an eight-octet encoded offset. Nonfinal
endpoints are aligned in that original coordinate space.

The native extended/extended secured MAC budget is 127 - 2 FCS - 27 MAC/security
header - 4 MIC = 94 adaptation bytes. For a full 1280-byte packet with full UDP
ports, FRAG1 represents 128 original bytes on canonical LL links or 96 with
fully inline mesh-local addresses. Subsequent nonfinal data ranges contain 88
original bytes; these common forms emit 15 secured frames. No security counters
are taken for planning/admission. Every distinct fragment allocates/reserves a
fresh counter before encryption; MAC retries reuse only the exact same
prepared frame. Tags advance only on successful whole-datagram admission,
wrap 65535 to zero, avoid currently owned tags, and initially use the restored
MAC counter's low 16 bits without changing any persistent settings format.

Forwarder resources are bounded and shared with indirect/in-flight traffic:

| Resource | Bound |
|---|---:|
| Owned TX descriptors/datagrams | Existing 100-entry bound, shared direct/indirect/in-flight |
| Owned original TX packet bytes | 5120 bytes (four maximum-MTU packets) |
| Logical pending TX frames/fragments | 100, including in-flight |
| Incomplete RX contexts | 4 |
| Owned RX packet bytes | 2560 bytes (two maximum-MTU packets) |
| Per-context disjoint byte ranges | 160 fixed slots, not a growing fragment slice |
| Completed/rejected tag suppression | 16 entries, at most 60 seconds |

`Forwarder.GetBufferUsage()` reports owned packet bytes, datagrams, and remaining
TX fragments; read it through `Do` while running. Admission is transactional:
resource shortage returns `mesh.ErrQueueFull` without taking a tag/security
counter or retaining part of a datagram. The entire owned packet remains charged
through final completion/failure. Success advances the original-byte offset;
final noACK/CCA/radio/build/persistence failure discards unsent fragments,
records a datagram drop, releases its bytes, and allows later queued traffic
to progress. `TxFragment` counts distinct prepared fragments (not retries);
`TxDirect` counts completed datagrams. RF delivery is not an all-or-nothing
transaction: a receiver cannot know a sender's later failure.

RX reassembly keys include full source/destination EUI-64 identity, PAN,
channel, security status, tag, and size. Known short MAC addresses, including
short address zero, are resolved to complete identity **only for authentication,
reassembly, and link metadata**. The actual encapsulating MAC address form is
kept separately for IPHC: SAM/DAM=11 under a short MAC reconstructs
`0000:00ff:fe00:XXXX` with the U/L bit zero; an extended EUI-64 instead inverts
the U/L bit ([RFC 6282 section 3.2.2](https://www.rfc-editor.org/rfc/rfc6282#section-3.2.2)).
Resolved factory identity cannot replace a short-zero address in that mapping.
The fragmented Thread
path requires authenticated MAC data. It expands FRAG1 before placing ranges,
supports FRAGN-before-FRAG1/out-of-order and exact duplicates, rejects conflicting
overlaps or contradictory sizes, and validates final UDP lengths/checksum
before one application dispatch. Unsupported NHC chains, stateful contexts
without context plumbing, checksum elision, and malformed/truncated headers
are refused rather than guessed. Rejected known datagrams release their state.
The fixed reassembly lifetime starts with the first received fragment, never
extends on duplicates, and expires at 60 seconds using monotonic time.

Completed/rejected tags are suppressed only within the bounded 16-entry/60-second
window; this is not an unbounded replay cache or a replacement for MAC replay
protection or Matter MRP. ThreadStop/Stop clear partial fragmented TX/RX state;
IfConfigDown clears all forwarding resources. A frame already handed to a radio
may finish, and normal radio completion/timeout guarantees are still required.
Late completion cannot revive/retry a disabled frame or complete a newer frame
after re-enable; see the mandatory submission-origin contract below.
Unfragmented Stop behavior and all executor cancellation guarantees are retained.

The standalone `Forwarder.FragmentMessage` utility now takes **uncompressed
IPv6 packets**, emits standard uncompressed IPv6 dispatch in FRAG1, and treats
its size argument as the whole adaptation-payload budget. Passing compressed
buffers as original datagrams was never a standard wire representation; those
simulation fixtures have been migrated. The real TX path uses the shared
compressed-header plan and existing MAC/security allocator instead.

The packet-byte/count caps bound retained protocol storage, not total
Instance/application/driver/Go-runtime RAM. Structural storage is checked in
tests; allocator/map buckets, GC, transient compression/crypto buffers, and
application-owned receive queues require their own SRAM budget. Full consumer
PASE, external MAC/OpenThread interoperability, and physical RF/flash behavior
remain separate integration evidence, not consequences of a compile or fake-radio
packet exchange. General FTD routing/EID resolution, sleepy delivery, multicast and discovery
remain unsupported; only the qualified MTD parent-handoff exception described
above accepts additional non-LL final unicast peers.

### Radio submission origin and borrowing

`GetTransmitBuffer`/`SubMac.GetTransmitFrame` expose a reusable **staging**
buffer, never a completion identity. SubMac gives each `Radio.Transmit` attempt
an owned bounded frame/metadata snapshot and a nonzero opaque
`TxInfo.SubmissionID`. The ID is assigned before submission, process-unique,
not reused on disable/re-enable, and independent of MAC security counters and
persistent settings.

**Driver contract:** accept the supplied frame rather than requiring the staging
object's pointer. Capture its SubmissionID at submission and echo it unchanged
in transmit-start/completion callbacks. Queue-owned Frame/TxInfo value copies
are explicitly supported. Never obtain a pending event's ID from a mutable
current TX slot or `GetTransmitBuffer` when dispatching that event. A driver
whose hardware cannot identify an old event must actually quiesce/drain it
before accepting another TX, not fabricate a new ID at arrival.

SubMac rejects stale/zero IDs before touching a current attempt's timer or state.
Deferred upper-MAC completions retain validated origin and are invalidated by a
new send/disable; scheduled backoff/ACK timers retain their operation/attempt
owner too. Callback frame/ACK data is borrowed: SubMac copies retained callback
data before deferral or retry. A software retry preserves the exact radio-updated
PSDU/security metadata and MAC counter but receives a **new attempt ID**.
Staging metadata retains its existing values/pointer, with ID zero, and cannot
alias a submitted snapshot.

Method signatures remain source-compatible, but an adapter that reports a
current staging buffer as an old completion is **not semantically compatible**.
Existing frame value-copy implementations can carry the added field without an
exact-object-pointer requirement, but their submission-to-IRQ/event discipline
still requires verification before upgrading. No external adapter was changed
or hardware quiescence asserted by this library fix.

### Persistent datasets and secured counters

`Config.Settings` backs the active and pending dataset managers as well as
key-sequence and MAC/MLE counter reservations. Nil settings retain the existing
volatile behavior; they are not safe for reusing credentials across a reboot.
The platform owns storage initialization, encryption/access control, and wear
leveling. No hardware-specific storage implementation is required by gothread.

Provision a fresh settings namespace through the instance before starting:

```go
inst := instance.New(instance.Config{Settings: durableSettings, Radio: driver})
if err := inst.PersistenceError(); err != nil {
    return err
}
// Only provision when commissioning a genuinely new network identity.
// On subsequent boots, let New restore the existing datasets.
if err := inst.ActiveDataset().SaveLocalFromInfo(&activeInfo); err != nil {
    return err
}
if err := inst.PendingDataset().SaveLocalFromInfo(&pendingInfo); err != nil {
    return err
}
if err := inst.Start(); err != nil {
    return err
}
return inst.Do(ctx, func() error {
    if err := inst.IfConfigUp(); err != nil {
        return err
    }
    return inst.ThreadStart()
})
```

`ActiveDataset()` and `PendingDataset()` expose the existing MeshCoP managers.
Their `Save`, `SaveLocal`, `SaveLocalFromInfo`, and `Clear` operations return
storage errors and leave manager state unchanged on failure. Previously void
mutation methods now return errors; ordinary statement-style calls still compile,
but callers must check the result. `Read`/`ReadInfo` preserve read errors.
`New` retains its existing signature; `PersistenceError`, `Start`, `IfConfigUp`,
and `ThreadStart` expose restoration failures. Perform stack operations before
`Start` or serialize them on the event loop with `Do`.

The settings adapter must meet these requirements:

- Return `platform.ErrSettingsNotFound` (possibly wrapped) only for missing
  keys/indexes. Report corruption and I/O failures as errors, not missing data.
- Atomically replace each value in `Set` and make it durable **before returning
  success**. After a failed write, either the old or the new complete value may
  exist. Counter write failures latch a fail-closed error until a fresh instance
  restores durable state.
- Give each node an exclusive settings namespace. Never share it between live
  instances, roll it back to a snapshot, or restore only the credentials.
  Settings must survive power cuts, not merely flush during shutdown.

Datasets use the active/pending setting keys. The versioned, checksummed
`SettingsKeyNetworkInfo` record stores a network-key fingerprint, key sequence,
and exclusive MAC/MLE counter upper bounds. It is internal gothread state, not an
OpenThread binary settings format. An existing dataset without this counter
record is rejected: importing a dataset alone cannot prove its previous counter
usage. Do not delete the counter record to recover an exhausted or corrupt store;
recommission with genuinely new credentials/identity instead.

Counter ranges contain 1024 values and are reserved before encryption. A reboot
resumes at the stored upper bounds, skipping unused values. MAC allocation occurs
when a queued frame is built, not when metadata is queued, so multiple queued
messages cannot reuse a counter. MLE allocation happens before message encryption.
Persistent counters stay globally monotonic across network-key and key-sequence
changes, including returning to an earlier key. `math.MaxUint32` is an exhausted
sentinel, never a transmitted counter; allocation returns
`key.ErrFrameCounterExhausted` instead of wrapping. Exhaustion is not automatically
cleared by key rotation.

**Scope and limitations:** This protects the instance's managed software-secured
MAC/MLE transmit paths, not application-crafted raw frames, direct radio/SubMac
transmissions, or manual mutation of reservation state through lower-level APIs.
Persistent operation rejects radios advertising `radio.CapTransmitSec`: autonomous
offload/secured enhanced ACK counters cannot be constrained by the current radio
interface. Software-encrypted frames carry `TxInfo.IsSecurityProcessed = true`.
MAC frame-build failures are logged and reported as dropped frames; storage
failures are also observable through `PersistenceError`. MLE send errors are
returned directly. The platform must preserve the node's extended address.
Pending datasets are restored, but their saved delay is not reduced by powered-off
time; no RTC-based pending activation or full routing/neighbor restoration is
provided here. Host reboot/fault tests do not establish flash endurance,
power-loss atomicity, or RF interoperability on actual hardware.

### Event (notifier bitmask)

```go
type Event uint32
const (
    EventIPv6AddressAdded      Event = 1 << 0
    EventIPv6AddressRemoved    Event = 1 << 1
    EventThreadRoleChanged     Event = 1 << 2
    EventThreadNetDataChanged  Event = 1 << 7
    EventThreadChildAdded      Event = 1 << 8
    EventThreadChildRemoved    Event = 1 << 9
    EventChannelChanged        Event = 1 << 10
    EventActiveDatasetChanged  Event = 1 << 12
    EventPendingDatasetChanged Event = 1 << 13
)
```


## 2. Radio Interface — `radio`

### State & Caps

```go
type State uint8
const (
    StateDisabled State = 0; StateSleep State = 1
    StateReceive  State = 2; StateTransmit State = 3
)

type Caps uint16
const (
    CapNone Caps = 0; CapAckTimeout Caps = 1 << 0
    CapEnergyScan Caps = 1 << 1; CapTransmitRetries Caps = 1 << 2
    CapCsmaBackoff Caps = 1 << 3; CapSleepToTx Caps = 1 << 4
    CapTransmitSec Caps = 1 << 5; CapTransmitTiming Caps = 1 << 6
    CapReceiveTiming Caps = 1 << 7; CapRxOnWhenIdle Caps = 1 << 8
)
func (c Caps) Has(capability Caps) bool
```

### Frame, TxInfo, RxInfo

```go
type Frame struct {
    PSDU      []byte   // PHY payload (max 127 bytes)
    Channel   uint8
    RadioType uint8
    TxInfo    *TxInfo  // non-nil for TX
    RxInfo    *RxInfo  // non-nil for RX
}

type TxInfo struct {
    SubmissionID uint64 // opaque per-attempt origin; captured/echoed by driver
    MaxCsmaBackoffs, MaxFrameRetries, RxChannelAfterTx uint8
    TxPower int8; Timestamp uint64
    CsmaCaEnabled, IsHeaderUpdated, IsARetx, IsSecurityProcessed, CslPresent bool
}

type RxInfo struct {
    Timestamp uint64; AckFrameCounter uint32
    AckKeyID uint8; RSSI int8; LQI uint8
    AckedWithFramePending, AckedWithSecEnhAck bool
}
```

### Radio Interface (full)

```go
type Radio interface {
    Enable() error; Disable() error
    IsEnabled() bool; GetState() State

    Sleep() error
    Receive(channel uint8) error
    Transmit(frame *Frame) error
    GetTransmitBuffer() *Frame

    GetCaps() Caps
    GetIEEEEui64() [8]byte
    SetPanID(panID uint16)
    SetExtendedAddress(addr types.ExtAddress)
    SetShortAddress(addr types.ShortAddress)
    GetTransmitPower() (int8, error)
    SetTransmitPower(power int8) error
    GetPromiscuous() bool; SetPromiscuous(enable bool)
    GetRSSI() int8
    GetSupportedChannelMask() uint32
    GetPreferredChannelMask() uint32
    GetReceiveSensitivity() int8

    EnableSrcMatch(enable bool)
    AddSrcMatchShortEntry(addr types.ShortAddress) error
    AddSrcMatchExtEntry(addr types.ExtAddress) error
    ClearSrcMatchShortEntry(addr types.ShortAddress) error
    ClearSrcMatchExtEntry(addr types.ExtAddress) error
    ClearSrcMatchShortEntries()
    ClearSrcMatchExtEntries()

    SetMacKey(keyIDMode, keyID uint8, prevKey, currKey, nextKey types.KeyMaterial)
    SetMacFrameCounter(counter uint32)
    SetMacFrameCounterIfLarger(counter uint32)

    EnergyScan(channel uint8, duration uint16) error
}
```

### Callbacks (radio → stack)

```go
type Callbacks interface {
    HandleReceiveDone(frame *Frame, err error)
    HandleTransmitStarted(frame *Frame)
    HandleTransmitDone(frame *Frame, ackFrame *Frame, err error)
    HandleEnergyScanDone(maxRSSI int8)
}
```


## 3. Platform Abstraction — `platform`

```go
type Alarm interface {
    Start(t0, dt uint32)  // fire at t0+dt milliseconds
    Stop()
    GetNow() uint32
}

type AlarmMicro interface {  // optional, for CSL
    StartMicro(t0, dt uint32); StopMicro(); GetNowMicro() uint32
}

type Entropy interface {
    Fill(buf []byte) error  // cryptographic random bytes
}

type Settings interface {
    Get(key SettingsKey, index int) ([]byte, error)
    Set(key SettingsKey, value []byte) error
    Add(key SettingsKey, value []byte) error    // list-type append
    Delete(key SettingsKey, index int) error    // -1 = delete all
    Wipe() error                               // factory reset
}

type Logger interface {
    Log(level LogLevel, region LogRegion, msg string)
}

type LogLevel uint8
// LogLevelNone=0, LogLevelCrit=1, LogLevelWarn=2,
// LogLevelNote=3, LogLevelInfo=4, LogLevelDebg=5

type Resetter interface {
    Reset(reason ResetReason)
    GetResetReason() ResetReason
}
```


## 4. MAC Layer — `mac/`

### mac/types — Addressing Primitives

```go
type ExtAddress [8]byte             // IEEE 802.15.4 Extended Address (8 bytes)
func (a *ExtAddress) IsGroup() bool
func (a *ExtAddress) SetLocal(local bool)
func (a *ExtAddress) ToggleLocal()
func (a *ExtAddress) CopyTo(dst []byte, order ByteOrder)
func (a *ExtAddress) Set(src []byte, order ByteOrder)
func (a ExtAddress) ToString() string

type ShortAddress uint16
const BroadcastAddress   ShortAddress = 0xffff
const ShortAddressInvalid ShortAddress = 0xfffe

type PanID uint16
const BroadcastPanID PanID = 0xffff

type Address struct { /* tagged union: None | Short | Extended */ }
func (a *Address) GetType() AddressType
func (a *Address) IsShort() bool; func (a *Address) IsExtended() bool
func (a *Address) GetShort() ShortAddress
func (a *Address) GetExtended() ExtAddress
func (a *Address) SetShort(s ShortAddress)
func (a *Address) SetExtended(e ExtAddress)
func (a *Address) IsBroadcast() bool
func (a *Address) Equal(other *Address) bool

type Key [16]byte                   // 128-bit MAC key
type KeyMaterial struct { /* wraps Key */ }
func (km *KeyMaterial) GetKey() Key
func (km *KeyMaterial) SetKey(k Key)
```

### mac/frame — 802.15.4 Frame Parsing

```go
type Frame struct { /* wraps raw PSDU */ }
func NewFrame(psdu []byte) Frame

func (f *Frame) GetType() Type         // TypeBeacon, TypeData, TypeAck, TypeMacCmd
func (f *Frame) GetVersion() Version   // Version2003, Version2006, Version2015
func (f *Frame) GetSequence() uint8
func (f *Frame) IsSecurityEnabled() bool
func (f *Frame) IsAckRequest() bool

func (f *Frame) GetDstPanID() (types.PanID, error)
func (f *Frame) GetDstAddr() (types.Address, error)
func (f *Frame) GetSrcPanID() (types.PanID, error)
func (f *Frame) GetSrcAddr() (types.Address, error)

func (f *Frame) GetSecurityLevel() SecurityLevel
func (f *Frame) GetKeyIDMode() KeyIDMode
func (f *Frame) GetFrameCounter() (uint32, error)
func (f *Frame) GetKeyID() (uint8, error)

func (f *Frame) GetHeaderLength() (uint8, error)
func (f *Frame) GetPayload() ([]byte, error)
func (f *Frame) GetFooterLength() uint8
```


## 5. Thread Mesh — `thread/mesh`

### FrameContext & SecurityMaterial

```go
type FrameContext struct {
    SrcShortAddr, DstShortAddr uint16
    SrcExtAddr, DstExtAddr     [8]byte
    UseSrcShort, UseDstShort   bool
    PanId                      uint16
    SecurityEnabled            bool
    Security                   SecurityMaterial
    AckRequest                 bool
    SequenceNumber             uint8
    FramePending, IEPresent    bool
}

type SecurityMaterial struct {
    KeyIdMode    uint8
    KeyId        uint8
    Key          [16]byte
    FrameCounter uint32
}
```

### Framer

```go
func NewFramer() *Framer

func (f *Framer) GetHeaderSize(ctx *FrameContext) int
func (f *Framer) GetMaxPayloadSize(ctx *FrameContext) int
func (f *Framer) BuildDataFrame(ctx *FrameContext, payload []byte) ([]byte, error)
func (f *Framer) BuildMleFrame(ctx *FrameContext, mlePayload []byte) ([]byte, error)
func (f *Framer) ParseFrameHeader(frame []byte) (*FrameContext, int, error)
```

### Security

```go
func BuildNonce(extAddr [8]byte, frameCounter uint32, secLevel uint8) [13]byte

func DecryptFramePayload(
    frame []byte, payloadOffset int, ctx *FrameContext,
    key [16]byte, srcExtAddr [8]byte,
) ([]byte, error)
```


## 6. Network Layer — `net/`

### net/ip6 — IPv6

```go
type Address [16]byte
func AddressFromString(s string) (Address, error)
func (a Address) ToString() string

type SockAddr struct { Address Address; Port uint16 }

type MessageInfo struct {
    SockAddr, PeerAddr Address
    SockPort, PeerPort uint16
    HopLimit           uint8
    LinkInfo           *LinkInfo  // MAC metadata (RX only)
}
```

### net/udp — UDP Sockets

```go
type ReceiveHandler func(payload []byte, messageInfo *ip6.MessageInfo)

type Socket struct { /* unexported */ }
func (s *Socket) IsBound() bool
func (s *Socket) GetSockName() ip6.SockAddr
func (s *Socket) GetPeerName() ip6.SockAddr

type NetifIdentifier uint8
const (
    NetifUnspecified    NetifIdentifier = 0
    NetifThreadHost     NetifIdentifier = 1
    NetifThreadInternal NetifIdentifier = 2
    NetifBackbone       NetifIdentifier = 3
)
```

### net/coap — CoAP Protocol (RFC 7252)

```go
type Type uint8  // TypeConfirmable=0, TypeNonConfirmable=1, TypeAck=2, TypeReset=3
type Code uint8  // CodeGet=0x01, CodePost=0x02, CodePut=0x03, CodeDelete=0x04, ...

type Message struct { /* wire-format data */ }
func NewMessage(typ Type, code Code, messageID uint16) *Message
func (m *Message) SetToken(token []byte) error

type Engine struct { /* unexported */ }
func NewEngine(sender Sender) *Engine
func (e *Engine) AddResource(r *Resource)
func (e *Engine) RemoveResource(uriPath string)
func (e *Engine) SetDefaultHandler(h RequestHandler)
func (e *Engine) SendMessage(msg *Message, info MessageInfo,
    txParams *TxParameters, handler ResponseHandler) error
func (e *Engine) Receive(data []byte, info MessageInfo)
func (e *Engine) AbortTransaction(handler ResponseHandler) error
func (e *Engine) Stop()

type Sender          func(data []byte, info MessageInfo) error
type ResponseHandler func(msg *Message, info MessageInfo, err error)
type RequestHandler  func(msg *Message, info MessageInfo)
type Resource        struct { URIPath string; Handler RequestHandler }
type TxParameters    struct { AckTimeout uint32; MaxRetransmit uint8; ... }
```


## 7. Simulation Platform — `platform/simulation`

### Platform Bundle

```go
type Platform struct {
    Alarm    *SimAlarm     // platform.Alarm  — time.Now() monotonic
    Entropy  *SimEntropy   // platform.Entropy — crypto/rand
    Settings *SimSettings  // platform.Settings — in-memory map
    Logger   *SimLogger    // platform.Logger  — log.Printf
    Radio    *SimRadio     // radio.Radio      — state machine + Medium
}
func NewPlatform() *Platform
```

### SimRadio

```go
func NewSimRadio() *SimRadio
func (r *SimRadio) SetMedium(m *Medium)
func (r *SimRadio) DeliverFrame(frame *radio.Frame)
func (r *SimRadio) ReceiveFrame() *radio.Frame
func (r *SimRadio) SetReceiveCallback(cb func(*radio.Frame))
```

### Medium — Shared RF Simulation

```go
type Medium struct { /* unexported */ }
func NewMedium() *Medium
func (m *Medium) Register(r *SimRadio)
func (m *Medium) Unregister(r *SimRadio)
func (m *Medium) Broadcast(sender *SimRadio, frame *radio.Frame) int
```

**Multi-node example:**

```go
medium := simulation.NewMedium()
platA := simulation.NewPlatform()
platB := simulation.NewPlatform()
medium.Register(platA.Radio)
medium.Register(platB.Radio)
// Frames from A are delivered to B (same channel, StateReceive)
```

### UDPSimRadio — OpenThread Interop

```go
func NewUDPSimRadio(nodeID uint16) (*UDPSimRadio, error)
func NewUDPSimRadioWithPort(nodeID, portBase uint16) (*UDPSimRadio, error)
func (r *UDPSimRadio) Start() error
func (r *UDPSimRadio) Stop()
func (r *UDPSimRadio) SetReceiveCallback(cb func(*radio.Frame))
```

Wire format: `[channel][PSDU][CRC-16 LE]` → multicast `224.0.0.116:9000`.


## 8. Key Constants

```go
// radio
const FrameMaxSize       = 127    // max 802.15.4 PSDU
const Channel24GHzMin    = 11
const Channel24GHzMax    = 26

// mac/types
const ExtAddressSize     = 8
const KeySize            = 16

// net/udp
const TmfPort      uint16 = 61631

// net/coap
const HeaderSize         = 4
const MaxTokenLength     = 8
```

## 9. SRP Client Response and Retry State — `net/srp`

`Client` keeps its existing lifecycle, callback, sender and timer APIs. A
successful `UDPSender.Send` means only local send/queue acceptance. Registration,
refresh and withdrawal change to `Registered`/`Removed` only after a matching,
valid DNS UPDATE success response. A rejected update never calls the success
path, grants a lease, prunes a removed service, or emits a nil callback first.
RCODE errors retain the exact existing `dns.ResponseCodeToError` sentinel.

On rejection, timeout or immediate send failure, in-flight item states return to
their pending operations (`Adding -> ToAdd`, `Refreshing -> ToRefresh`,
`Removing -> ToRemove`). Each rejection/response timeout produces one error
callback for that attempt, with no removal-success list. Immediate build/send
errors preserve the baseline terminal-only `errors.ErrFailed` callback rather
than being relabeled as a response timeout. Nil callbacks do not
change acknowledgement semantics; successful removal still releases ownership.

Every successful send now arms an owned response deadline: this is **new wiring
for the missing baseline timer**, not pre-existing executed behavior. Response
deadline/retry waits use the existing, previously unused backoff scaffolding
(1800-ms minimum, 17/10 growth, 1,036,800-ms maximum, bounded jitter at most
interval/5 or 2000 ms) with the pinned OpenThread rejection/timeout retry
approach. Local build/send retries retain
the existing 250-ms base and up-to-10-ms jitter. There is no new shared
failure-count limit: the baseline eight-attempt `MaxTxFailureRetries`
budget applies **only to consecutive local build/send failures**, and a successful
send resets it as before. Response timeouts/rejections notify an error once per
attempt and remain pending/retryable with capped waits, without a new permanent
response-count hard stop. One owned timer and one in-flight update bound resources;
Stop/Pause/clear can explicitly stop retries. A matching ACK resets the response
backoff and schedules ordinary lease renewal. At the existing terminal **local
send** failure bound, the client is quiescent in `StateUpdated` with pending item
flags and no timer; the final error callback and item flags, not `StateUpdated`
alone, identify that failure. No response-count/lifetime registration exhaustion
policy has been introduced.

Timer callbacks carry their scheduling generation, and sender calls capture
attempt ownership before releasing the mutex. Matching responses,
Stop/Pause/clear, server or operation changes invalidate earlier deadlines and
queued callbacks. A stale/wrong ID, non-UPDATE/query/truncated header or malformed
success response cannot acknowledge the current attempt or cancel its deadline.
Only a completely parsed successful response commits granted lease data.
Callbacks and the sender execute without the client mutex, so they can call
lifecycle APIs; an old sender return or callback cannot attach a timer/outcome
to a replacement operation.

DNS has a 16-bit response ID, with no local generation carried on the wire.
IDs remain random and nonzero; only immediate reuse of the previous ID is avoided
(as in the pinned OpenThread implementation). There is **no lifetime uniqueness
or permanent ID-exhaustion counter**. Local timer/sender generations protect
queued callbacks, not indefinite late wire replies after an ID is eventually
reused. Current-message-ID matching cannot solve that protocol limitation.
`HandleResponse` receives bytes only: this repair does **not** validate the
network peer tuple, bind a native socket, or introduce server selection.

These library guarantees alone do not establish native SRP or DNS publication.
The explicit Instance binding below adds the supported native socket/key/loop
path; server selection, consumer discovery integration, DNS-SD/mDNS proxying,
upstream routing, physical hardware and full-node startup remain separate gates.

## 10. Explicit durable native SRP — `instance`

```go
type SRPConfig struct {
    Local, Server        ip6.SockAddr
    HostName, DomainName string
    Addresses           []ip6.Address
    Lease, KeyLease      uint32
}
func (inst *Instance) StartSRP(config SRPConfig) (*SRPBinding, error)
func (b *SRPBinding) UpsertService(service srp.Service) (uint64, error)
func (b *SRPBinding) WithdrawService(name, instanceName string) (uint64, error)
func (b *SRPBinding) WithdrawHost(removeKeyLease bool) (uint64, error)
func (b *SRPBinding) Pause() error
func (b *SRPBinding) Resume() error
func (b *SRPBinding) Stop() error
func (b *SRPBinding) Notices() <-chan SRPNotice
func (b *SRPBinding) Err() error
```

Start and mutations are **loop-only**; external callers use one `Do`, without
waiting for responses inside it. `Notices` and terminal `Err` can be read outside
the loop. One live binding exclusively owns its private client/socket/timer.
Do not mix it with the legacy standalone `Instance.SrpClient()` scaffold.

```go
var binding *instance.SRPBinding
err := inst.Do(ctx, func() error {
    var err error
    binding, err = inst.StartSRP(instance.SRPConfig{
        Local: localTuple, Server: configuredServer, HostName: hostLabel,
        Addresses: assignedAdvertisedAddresses,
    })
    return err
})
if err != nil {
    return err
}
err = inst.Do(ctx, func() error {
    _, err := binding.UpsertService(service)
    return err
})
// In the application's existing outside-loop result consumer, process
// binding.Notices(); after channel closure ALWAYS inspect binding.Err().
```

Both ports are explicit/nonzero; local port collisions and intercepted protocol
ports fail before key/socket side effects. The source must pass the existing
public `SendUDP` qualified direct/awake-MTD-parent checks; no private broadcast
fallback or local UDP reinjection is used. Advertised addresses are a separate,
explicit nonempty list of valid non-link-local Netif assignments, not inferred
OMRs or computed RLOCs. Assignment is not proof of end-to-end routability.
Peer/local address+port, response header and current ID are checked before owned
bounded RX admission. The loop defers RX work until outside MAC's receive lock.
Source/route/network prerequisites are captured and revalidated, never silently
retargeted. There is no auto server selection.

Config/service inputs and nested notice data are deep-owned. Admission nil
means queued intent, **not an ACK**. Services have identity `(Name,InstanceName)`;
pre-send replacements coalesce, and superseded tokens have no promised outcome.
Mutations during an in-flight attempt return `ErrInvalidState`. The returned
`uint64` and `SRPNotice.Revision` are binding-local admission **high-waters**,
not per-operation completions or generations shared across handles.
Upsert/replace also rejects pending or completed **global host withdrawal**;
stop and start a new binding to register a host again. This is distinct from
coalescing a queued per-service withdrawal with its replacement.

`SRPNotice` has `Err error`, `Revision uint64`, `State srp.State`,
`Host srp.HostInfo`, and `Services, RemovedServices []srp.Service`. On nil Err,
the service slices contain **only complete immutable inputs accepted by THIS
response**, captured before its actual send. Other retained Registered services
are excluded. A host-only ACK may contain no service ACKs. Consumers must match
desired full content and actual accepted/removed subset, not assume a high-water
acknowledges all pending work. For example, after a renewal error invalidates
whole-advertisement health, a B-only ACK cannot restore A's health.

Error notices preserve typed RCODE/timeout or the original terminal send cause,
pending state and ownership. Response failures remain retryable/open. Eight
consecutive local build/send failures close this binding with its final cause;
standalone client callback behavior remains unchanged. Actual server-granted
expiry is **unknown** to this interface: requested Lease and Registered flags
do not establish future lease liveness. Conservatively invalidate consumer
health on errors/pause/closure until fresh matching ACKs cover the desired set.

Bounds are eight services, four advertised addresses, five subtypes/service,
512 encoded TXT bytes/service, eight notices and eight queued RX payloads,
using the Instance's existing bounded task admission. The binding selects
single-service UPDATEs so six services (five fabrics plus one commissionable
with five subtypes) can be retained without requiring one oversized datagram.
The real encoder, public KEY and fixed 64-byte SIG placeholder measure each
service's complete signed-update size before admission: over 1232 bytes or
other limits return explicit errors, never truncation. Sizing does not sign,
consume entropy, submit frames, or allocate counter/tag reservations.
Single-service requested leases use that service's values or configured
7200/604800-second defaults. Empty DomainName uses `default.service.arpa.`.

A full notice/RX/task queue fail-closes with `ErrNoBufs`, releasing socket and
timers; buffered earlier ACKs remain readable. Always inspect Err on closure,
even after a previous nil notice. No dropped ACK is silently treated as success.
Pause cancels the attempt but retains port/owned data. It queues an explicit
deep-owned `StatePaused`, nil-Err notice with empty service ACK subsets: this is
nonterminal health invalidation, **not an ACK** or backend failure. A full queue
still fail-closes with ErrNoBufs. Resume revalidates the original prerequisites
and re-admits retained registrations for fresh actual single-service ACKs;
it never silently blesses old Registered states. Consumer health remains
unknown until fresh ACKs cover the entire desired set. Standalone Client.Pause
retains its existing behavior. Binding Stop, ThreadStop, interface down and
Instance.Stop cancel timers, close the port and fence old queued work.
**Stop is local cleanup, not remote withdrawal.** Withdraw and await the actual
matching removal ACK before shutdown, or explicitly accept remote lease expiry.
A failed withdrawal remains pending/retryable; it is not a successful close.

Durable binding requires both Settings and qualified Entropy. The existing
canonical SRP slot `0x000b` holds one 41-byte record: `SRPK`, version1, canonical
32-byte P-256 secret scalar, and big-endian CRC32-IEEE over the first37 bytes.
Backend atomic durable Set must succeed **before the first signed UPDATE**;
only genuine missing-setting errors permit generation. Corrupt/wrong-version/
invalid-scalar/read failures never erase/regenerate. An ambiguous write failure
latches this Instance closed; a fresh Instance may reopen a complete validated
record. CRC detects accidental corruption, not malicious tampering. Backend
confidentiality/access control, atomicity, physical durability and entropy
quality are preconditions, not claims established by software fakes. Key creation
and every SIG0 signature use the supplied Entropy reader without global RNG
replacement. MAC/MLE durable counter reservation remains independent/unchanged.
See the numeric namespace compatibility warning at the top of this document.

## Further Reading

- Full godoc: `go doc github.com/hilli/gothread/...`
- `platform/simulation/integration_test.go` — multi-node simulation tests
- `thread/mesh/framer_test.go` — frame building/parsing examples
