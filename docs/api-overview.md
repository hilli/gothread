# GoThread API Overview

A curated guide to the most important public types in
**github.com/hilli/gothread** — a pure-Go implementation of Thread 1.4.0.

> Not a full godoc dump — highlights key types, relationships, and signatures.

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

The initial supported routes are only **direct valid rx-on-when-idle neighbors**,
including an established parent: canonical EUI-64-derived link-local peers, or
RLOC peers with the current mesh-local prefix. Unknown/unresolved EIDs, sleepy
children, other prefixes, anycast, multi-hop/off-mesh routes, and self-delivery
return `errors.ErrNoRoute`. Multicast/group/discovery, including mDNS, is not
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
packet exchange. General routing, unresolved EIDs, sleepy delivery, multicast,
and discovery remain unsupported by the native boundary.

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

## Further Reading

- Full godoc: `go doc github.com/hilli/gothread/...`
- `platform/simulation/integration_test.go` — multi-node simulation tests
- `thread/mesh/framer_test.go` — frame building/parsing examples
