# gothread Architecture

A comprehensive architecture and implementation guide for **gothread** — a
pure Go implementation of the Thread 1.4.0 networking protocol, ported from
[OpenThread](https://github.com/openthread/openthread).

Verified against OpenThread commit `3f11074f1e188bd84d7d530da271ce5bc66bc3ec`.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Layer Architecture](#layer-architecture)
3. [Data Flow](#data-flow)
4. [Instance Architecture](#instance-architecture)
5. [Security Model](#security-model)
6. [Platform Abstraction](#platform-abstraction)
7. [Package Map](#package-map)
8. [Key Design Decisions](#key-design-decisions)

---

## System Overview

### What is gothread?

gothread is a from-scratch Go implementation of the complete Thread 1.4.0
networking protocol stack. Thread is a low-power, IPv6-based mesh networking
protocol for IoT devices that runs over IEEE 802.15.4 radio. gothread
provides:

- IEEE 802.15.4 MAC layer with AES-CCM security
- 6LoWPAN header compression (RFC 6282)
- Mesh Link Establishment (MLE) for topology formation
- Mesh routing with route cost calculation
- IPv6 networking with UDP, ICMPv6, CoAP, and TCP
- MeshCoP commissioning (Commissioner, Joiner, Border Agent)
- Border Router support (ND proxy, DHCPv6-PD, NAT64)
- Backbone Router (DUA, MLR, multicast forwarding)
- DNS-SD, SRP, mDNS service discovery

### Relationship to OpenThread

gothread is a **structural port** of OpenThread's C++ codebase. The
translation approach is:

| OpenThread (C++)                      | gothread (Go)                          |
|---------------------------------------|----------------------------------------|
| `class Foo : public InstanceLocator`  | Package-level struct `Foo`             |
| `Instance::Get<Foo>()`                | Field on `instance.Instance`           |
| `Foo::HandleTimer()`                  | Closure or method registered as timer  |
| C++ templates / virtual dispatch      | Go interfaces                          |
| `#if OPENTHREAD_CONFIG_*`             | Always-compiled (build tags if needed) |
| Global `otPlatAlarm*` functions       | `platform.Alarm` interface             |
| `otError` enum                        | Go `error` values                      |

The module structure mirrors OpenThread's `src/core/` directory layout:

```
OpenThread src/core/          gothread
─────────────────────         ─────────────
thread/key_manager.cpp    →   thread/key/key_manager.go
thread/lowpan.cpp         →   thread/lowpan/lowpan.go
thread/mesh_forwarder.cpp →   thread/mesh/forwarder.go
mac/mac.cpp               →   mac/mac.go
mac/sub_mac.cpp            →   mac/submac/submac.go
net/ip6.cpp               →   net/ip6/
common/instance.cpp       →   instance/instance.go
```

### Module Boundary

gothread is a single Go module (`github.com/hilli/gothread`). The protocol
stack uses only the Go standard library; the UDP simulation radio uses
`golang.org/x/sys/unix` for platform-specific socket constants. All cryptographic
primitives (AES-CCM, HMAC-SHA256, HKDF, ECDSA, PBKDF2) are implemented
in-tree under `crypto/`.

---

## Layer Architecture

The Thread protocol stack is organized in layers. Each layer has a clear
Go package boundary.

```
┌─────────────────────────────────────────────────────────────────────┐
│                      APPLICATION LAYER                              │
│                                                                     │
│  meshcop/         MeshCoP commissioning (Commissioner, Joiner,     │
│                   Border Agent, Dataset management, TCAT)           │
│  net/srp/         Service Registration Protocol (client + server)  │
│  net/dnssd/       DNS-SD service discovery                         │
│  net/dnssdserver/ DNS-SD query server                              │
│  net/mdns/        mDNS core                                        │
│  border/          Border Router (RoutingManager, OMR, DHCPv6-PD)   │
│  backbone/        Backbone Router (DUA, MLR, ND proxy)             │
│  diags/           Factory diagnostics                              │
├─────────────────────────────────────────────────────────────────────┤
│                       NETWORK LAYER                                 │
│                                                                     │
│  net/ip6/         IPv6 network interface + header construction     │
│  net/udp/         UDP socket management                            │
│  net/coap/        CoAP message exchange engine                     │
│  net/coaps/       CoAP over DTLS (secure CoAP)                    │
│  net/icmp6/       ICMPv6 echo + error handling                    │
│  net/dhcp6/       DHCPv6 client + server                          │
│  net/tcp/         TCP socket support                               │
│  net/slaac/       SLAAC address generation from on-mesh prefixes   │
│  net/mpl/         Multicast Protocol for LLNs                      │
│  net/nat64/       NAT64 IPv4 connectivity                         │
│  net/dns/         DNS client (A/AAAA, service browse/resolve)      │
│  net/sntp/        SNTP time queries                                │
├─────────────────────────────────────────────────────────────────────┤
│                       THREAD LAYER                                  │
│                                                                     │
│  thread/mle/      Mesh Link Establishment (attach, advertisements, │
│                   parent selection, child/router management)        │
│  thread/routing/  Router table, child table, neighbor table,       │
│                   route cost calculation                            │
│  thread/netdata/  Network Data (leader, local, publisher, notifier)│
│  thread/key/      Key manager (network key, MLE/MAC key derivation,│
│                   frame counters, key rotation)                     │
│  thread/tmf/      Thread Management Framework CoAP agent           │
│                   (Address Solicit/Release, Server Data Register)   │
│  thread/announce/ MLE Announce sender and handler                  │
│  thread/discover/ Thread network discovery scanner                 │
│  thread/indirect/ Indirect TX to sleepy end devices                │
│  thread/bbr/      BBR DUA + MLR managers                           │
│  thread/mgmt/     Energy scan + PAN ID query servers               │
│  thread/linkmetrics/ Link metrics (subject + initiator)            │
│  thread/supervision/ Child supervision, data poll sender/handler   │
├─────────────────────────────────────────────────────────────────────┤
│                        MESH LAYER                                   │
│                                                                     │
│  thread/mesh/     Mesh forwarding (Forwarder, TxMessage, Framer),  │
│                   IEEE 802.15.4 frame build/parse, AES-CCM encrypt, │
│                   6LoWPAN fragmentation headers                     │
│  thread/lowpan/   6LoWPAN IPHC header compression (RFC 6282),      │
│                   NHC UDP compression, fragment dispatch            │
├─────────────────────────────────────────────────────────────────────┤
│                        MAC LAYER                                    │
│                                                                     │
│  mac/             IEEE 802.15.4 MAC (scanning, beacon generation,  │
│                   operation priority scheduling, data poll)         │
│  mac/submac/      Sub-MAC: software CSMA-CA, retransmissions,      │
│                   ACK timeout, energy scanning                      │
│  mac/frame/       Frame parsing utilities                          │
│  mac/types/       ExtAddress, ShortAddress, KeyMaterial types      │
│  mac/filter/      Address allowlist / denylist                     │
│  mac/csl/         Coordinated Sampled Listening scheduler          │
│  mac/links/       Multi-radio link manager (802.15.4 + TREL)      │
│  mac/ie/          Information Elements                             │
│  mac/datapoll/    Data poll handler + sender                       │
│  mac/raw/         Raw link-layer frame access                      │
│  mac/wakeup/      Wake-up TX scheduling                            │
├─────────────────────────────────────────────────────────────────────┤
│                      PLATFORM LAYER                                 │
│                                                                     │
│  radio/           Radio interface (radio.Radio, radio.Frame,       │
│                   radio.Callbacks, state machine, capabilities)     │
│  radio/ble/       BLE secure transport                             │
│  radio/trel/      Thread Radio Encapsulation Link                  │
│  platform/        Platform interfaces (Alarm, Entropy, Settings,   │
│                   Logger, Time, Resetter)                           │
│  platform/simulation/  SimRadio (in-process), UDPSimRadio          │
│                        (OT-compatible UDP multicast), Medium       │
└─────────────────────────────────────────────────────────────────────┘
```

### Layer interactions (simplified):

```
  ┌──────────┐   CoAP/TMF    ┌──────────┐
  │   App    │ ◄────────────► │  Network │
  │ MeshCoP  │   UDP/IPv6    │  ip6/udp │
  │ SRP/DNS  │               │  coap    │
  └────┬─────┘               └────┬─────┘
       │                          │
       │          ┌───────────────┘
       │          │
       ▼          ▼
  ┌─────────────────────┐
  │     Thread Layer     │
  │  MLE + Routing +     │
  │  Key Manager +       │
  │  Network Data        │
  └──────────┬──────────┘
             │
             ▼
  ┌─────────────────────┐    ┌─────────────────┐
  │     Mesh Layer       │    │   6LoWPAN       │
  │  mesh.Forwarder      │───►│  lowpan.Compress│
  │  mesh.Framer         │    │  lowpan.Decomp  │
  │  mesh.BuildTxFrame   │    └─────────────────┘
  └──────────┬──────────┘
             │
             ▼
  ┌─────────────────────┐
  │      MAC Layer       │
  │  mac.Mac             │
  │  submac.SubMac       │
  │  (CSMA-CA, retries)  │
  └──────────┬──────────┘
             │
             ▼
  ┌─────────────────────┐
  │   Platform / Radio   │
  │  radio.Radio iface   │
  │  SimRadio / UDPSim   │
  └─────────────────────┘
```

---

## Data Flow

### RX Path: Radio → Application

When a frame arrives over the air:

```
  radio.Radio.Receive(channel)
       │
       │  Frame received by hardware/simulation
       ▼
  radio.Callbacks.HandleReceiveDone(frame *radio.Frame, err)
       │
       │  SubMac processes ACKs, filters duplicates
       ▼
  submac.Callbacks.ReceiveDone(frame, err)
       │
       │  Mac validates frame type, runs source match,
       │  updates link metrics
       ▼
  mac.Callbacks.HandleReceivedFrame(frame)
       │
       │  Instance dispatches based on frame content:
       │
       ├─► Is 6LoWPAN IPHC? (lowpan.IsLowpanHc)
       │     │
       │     ▼
       │   lowpan.DecompressHeader(compressed, macAddrs)
       │     → Reconstructs 40-byte IPv6 header from
       │       2-byte IPHC dispatch + inline fields
       │     → NHC decompresses UDP header if present
       │     │
       │     ▼
       │   mesh.Forwarder routes based on IPv6 dst:
       │     - Local delivery → ip6.Netif → udp/icmp/coap
       │     - Mesh forward   → re-queue to TX path
       │
       ├─► Is MLE? (UDP port 19788)
       │     → thread/mle/ dispatches by MLE command type
       │
       └─► Is mesh header? (dispatch 0b10xxxxxx)
             → Decrement hops-left, forward to next hop
```

**Key types on RX path:**

| Step              | Type                 | Package               |
|-------------------|----------------------|-----------------------|
| Raw frame         | `radio.Frame`        | `radio`               |
| Parsed MAC header | `mesh.FrameContext`  | `thread/mesh`         |
| Compressed IPv6   | `[]byte` (IPHC)     | `thread/lowpan`       |
| Decompressed IPv6 | `ip6.Header`         | `net/ip6`             |
| MAC addresses     | `lowpan.AddressContext` | `thread/lowpan`    |

### TX Path: Application → Radio

When the application sends a message:

```
  Application (e.g. MLE Advertisement, CoAP request)
       │
       │  Creates mesh.TxMessage with metadata:
       │    - Data (payload bytes)
       │    - MeshDest / MeshSource (RLOC16)
       │    - TxMetadata (IPv6 src/dst, ports, hop limit)
       ▼
  mesh.Forwarder.EnqueueDirect(msg *TxMessage)
       │
       │  Queued in direct TX queue (max 100 frames)
       ▼
  mac.Mac.RequestDirectFrameTransmission()
       │
       │  Mac selects highest-priority pending operation
       ▼
  Instance.HandleFrameRequest() callback
       │
       │  mesh.BuildTxFrame(msg, sequenceNumber) constructs:
       │    1. Build 40-byte IPv6 header from TxMetadata
       │    2. lowpan.CompressHeader() → IPHC compressed bytes
       │    3. lowpan.CompressUDPHeader() → NHC compressed
       │    4. Concatenate: IPHC + NHC_UDP + payload
       │    5. mesh.Framer.BuildDataFrame(ctx, lowpanPayload)
       │       → Builds FCF, addresses, aux security header
       │       → AES-CCM encrypts payload if security enabled
       ▼
  submac.SubMac.Send(frame *radio.Frame)
       │
       │  CSMA-CA backoff (if not handled by radio hardware)
       │  CCA (Clear Channel Assessment)
       ▼
  radio.Radio.Transmit(frame *radio.Frame)
       │
       │  Wait for ACK (if requested)
       │  Retry on failure (up to 15 retries for direct TX)
       ▼
  radio.Callbacks.HandleTransmitDone(frame, ackFrame, err)
```

**Key types on TX path:**

| Step                | Type                | Package             |
|---------------------|---------------------|---------------------|
| Queued message      | `mesh.TxMessage`    | `thread/mesh`       |
| IPv6/transport meta | `mesh.TxMetadata`   | `thread/mesh`       |
| MAC frame context   | `mesh.FrameContext` | `thread/mesh`       |
| IPHC compressed     | `[]byte`            | `thread/lowpan`     |
| Built MAC frame     | `[]byte`            | `thread/mesh`       |
| Radio frame         | `radio.Frame`       | `radio`             |

### Frame Construction Pipeline (TX detail)

```
  TxMessage.Data (app payload, e.g. CoAP body)
       │
       ▼
  ┌──────────────────────────────────────────────────────┐
  │  Step 1: IPv6 Header (40 bytes)                       │
  │  ip6.NewHeader(src, dst, nextHdr, hopLimit, payLen)   │
  └──────────────┬───────────────────────────────────────┘
                 │
                 ▼
  ┌──────────────────────────────────────────────────────┐
  │  Step 2: 6LoWPAN IPHC Compression                    │
  │  lowpan.CompressHeader(ipv6Raw, macAddrs, contexts)  │
  │                                                       │
  │  Compresses 40 bytes → typically 2-7 bytes:           │
  │  - Elides version/traffic class/flow label            │
  │  - Compresses common hop limits (1, 64, 255)          │
  │  - Elides src/dst addresses derivable from MAC addrs  │
  └──────────────┬───────────────────────────────────────┘
                 │
                 ▼
  ┌──────────────────────────────────────────────────────┐
  │  Step 3: NHC UDP Compression (if UDP)                 │
  │  lowpan.CompressUDPHeader(udpHdr)                    │
  │                                                       │
  │  Compresses 8-byte UDP header:                        │
  │  - Ports in 0xF0Bx range → 4-bit nibbles             │
  │  - Ports in 0xF0xx range → 8-bit values              │
  │  - Checksum elided (MAC security provides integrity)  │
  └──────────────┬───────────────────────────────────────┘
                 │
                 ▼
  ┌──────────────────────────────────────────────────────┐
  │  Step 4: IEEE 802.15.4 MAC Frame                      │
  │  mesh.Framer.BuildDataFrame(ctx, lowpanPayload)      │
  │                                                       │
  │  Header: FCF(2) + SeqNum(1) + PanID(2) +             │
  │          DstAddr(2|8) + SrcAddr(2|8) +                │
  │          [AuxSec: SecCtl(1)+Counter(4)+KeyId(1)]      │
  │                                                       │
  │  If security enabled:                                 │
  │    AES-CCM encrypt payload, append 4-byte MIC tag     │
  └──────────────────────────────────────────────────────┘
```

---

## Instance Architecture

### The Central Coordinator

`instance.Instance` is the heart of gothread. It owns every protocol module
as a struct field, creates them in `wireModules()`, and runs a
single-goroutine cooperative event loop.

```go
// instance/instance.go (simplified)
type Instance struct {
    // Platform interfaces
    alarm        platform.Alarm
    entropy      platform.Entropy
    platSettings platform.Settings
    logger       platform.Logger
    platRadio    radio.Radio

    // Event loop channels
    taskCh chan func()      // posted tasks
    stopCh chan struct{}     // shutdown signal
    doneCh chan struct{}     // completion signal

    // Timer scheduler (sorted list, processed on event loop)
    timers *timerScheduler

    // Notifier (event flags dispatched to callbacks)
    notifier *notifier

    // Tier 1 — Radio / MAC / Key core
    keyManager *key.Manager
    subMac     *submac.SubMac
    mac        *mac.Mac

    // Tier 2 — Routing / MLE / Network
    routerTable   *routing.RouterTable
    childTable    *routing.ChildTable
    neighborTable *routing.NeighborTable
    mleService    *mle.Service
    netif         *ip6.Netif
    udpManager    *udp.UDP

    // Tier 3 — Application layer
    coapEngine    *coap.Engine
    tmfAgent      *tmf.Agent
    netdataLeader *netdata.Leader
    forwarder     *mesh.Forwarder
    addrResolver  *addrresolver.Resolver

    // ... 80+ more module fields
}
```

### Event Loop

The event loop is a `select`-based loop running in its own goroutine. All
stack operations execute on this goroutine, eliminating the need for locks
within individual modules.

```go
func (inst *Instance) eventLoop() {
    for {
        select {
        case <-inst.stopCh:
            inst.drainTasks()
            return
        case fn := <-inst.taskCh:
            fn()
            inst.timers.processExpired()
            inst.notifier.process()
            inst.stackNotifier.Process()
        case <-timerCh:
            inst.timers.processExpired()
            inst.notifier.process()
            inst.stackNotifier.Process()
        }
    }
}
```

Three event sources drive the loop:

| Source       | Channel      | Purpose                               |
|-------------|--------------|---------------------------------------|
| Tasks       | `taskCh`     | Posted closures from any goroutine    |
| Timers      | `time.After` | Sorted timer list with cancel support |
| Stop signal | `stopCh`     | Graceful shutdown                     |

After each event, timers and notifier events are processed to propagate
any side effects.

### Timer Scheduler

Timers are maintained in a sorted slice (earliest-first). Each timer has
a fire time, callback function, and cancel flag:

```go
type timer struct {
    fireAt    time.Time
    fn        func()
    cancelled bool
}
```

`scheduleWithCancel()` returns a cancel function. This is used extensively
by SubMac (CSMA-CA backoff timers) and Mac (scan dwell timers).

The scheduler protects the queue and cancellation flags with one mutex,
allowing scheduling, cancellation, and deadline/count queries to run
concurrently with the event loop. Only the event loop dispatches callbacks.
It removes one due timer at a time and checks cancellation under the lock,
then invokes the callback without the lock. A callback can therefore
reschedule itself or cancel another due timer before it is dispatched.
Cancellation is idempotent and does not wait for an already-dispatched
callback. Cancelled timers remain queued until their deadlines are processed.
Each dispatch pass uses a fixed time cutoff; timers with deadlines after
that cutoff are handled on a later pass.

### Notifier System

Two levels of event notification:

1. **Instance-level notifier** — drives the event loop with `Event` bitmask
   flags (e.g., `EventThreadRoleChanged`, `EventThreadNetDataChanged`).
   Callbacks are registered by modules that need to react to state changes.

2. **Stack-level notifier** (`common/notifier`) — protocol-level event bus
   for dataset changes and similar cross-module notifications.

### Lifecycle

```
  New(config)        Create Instance, wire all modules
       │
  inst.Start()       Launch event loop goroutine
       │
  inst.IfConfigUp()  Enable MAC + mesh forwarder
       │
  inst.ThreadStart() Enable MLE → Detached → attach begins
       │
       │              ... Thread network operation ...
       │
  inst.ThreadStop()  MLE → Disabled, stop advertisements
       │
  inst.IfConfigDown() Disable MAC + forwarder
       │
  inst.Stop()        Signal event loop shutdown, wait
```

### The Adapters Pattern

Modules are designed as independent packages that cannot import each other.
The `instance/adapters.go` file (~2400 lines) contains **adapter types**
that bridge module interfaces. Examples:

| Adapter                    | Bridges                                    |
|----------------------------|--------------------------------------------|
| `submacCallbackBridge`     | SubMac.Callbacks → Mac (breaks circular)   |
| `settingsDriverAdapter`    | platform.Settings → csettings.Driver       |
| `routerCheckerAdapter`     | routing.RouterTable → netdata.RouterChecker |
| `macPollTransmitter`       | supervision → Mac.RequestDataPoll          |
| `borderAgentTransportAdapter` | border.Agent → Instance transport       |

The bridge pattern is critical for the SubMac ↔ Mac construction
dependency: SubMac needs a `Callbacks` at creation, Mac needs `SubMac`
at creation. A `submacCallbackBridge` starts empty and gets its target
set after both are constructed:

```go
bridge := &submacCallbackBridge{}
inst.subMac = submac.New(submac.Config{
    Radio:     inst.platRadio,
    Callbacks: bridge,
    ...
})
inst.mac = mac.New(mac.Config{
    SubMac:    inst.subMac,
    Callbacks: inst,
    ...
})
bridge.target = inst.mac  // now wired
```

---

## Security Model

### AES-CCM Encryption

Thread uses IEEE 802.15.4 MAC-layer security with AES-128-CCM (Counter
with CBC-MAC). The implementation lives in `crypto/aesccm/`:

```go
// crypto/aesccm/aesccm.go
type AesCcm struct {
    block cipher.Block  // AES-128 block cipher
}

func (c *AesCcm) Seal(nonce, plaintext, additionalData []byte, tagLen int) (ciphertext, tag []byte, err error)
func (c *AesCcm) Open(nonce, ciphertext, additionalData, tag []byte) (plaintext []byte, err error)
```

Parameters:
- **Nonce**: 13 bytes = ExtAddress(8) || FrameCounter(4) || SecurityLevel(1)
- **AAD**: MAC header bytes (everything before the payload)
- **Tag**: 4 bytes (MIC-32) for SecurityEncMic32 (level 5)
- **Key**: 16-byte AES key derived from the Thread Network Key

Nonce construction (`thread/mesh/security.go`):

```go
func BuildNonce(extAddr [8]byte, frameCounter uint32, securityLevel uint8) [13]byte {
    var nonce [13]byte
    copy(nonce[0:8], extAddr[:])
    binary.LittleEndian.PutUint32(nonce[8:12], frameCounter)
    nonce[12] = securityLevel
    return nonce
}
```

### Key Derivation

The `thread/key/` package manages all Thread security material:

```
  Thread Network Key (16 bytes, user-provisioned)
       │
       │  HMAC-SHA-256(key=NetworkKey, data=BigEndian(KeySequence) || "Thread")
       │
       ▼
  ┌──────────────────────────────────┐
  │  32-byte HMAC output             │
  │  bytes  0-15: MLE Key (16 bytes) │
  │  bytes 16-31: MAC Key (16 bytes) │
  └──────────────────────────────────┘
```

Key types (`thread/key/types.go`):

```go
type NetworkKey [16]byte  // User-provisioned master key
type Pskc       [16]byte  // Pre-Shared Key for Commissioner
type Kek        [16]byte  // Key Encryption Key
type MacKey     [16]byte  // Derived MAC encryption key
type MleKey     [16]byte  // Derived MLE encryption key
```

### Key Rotation

Thread rotates keys periodically (default: every 672 hours ≈ 28 days).
The key manager tracks:

- **Key sequence counter** — monotonically increasing
- **MAC frame counter** — per-key, prevents replay attacks
- **MLE frame counter** — separate counter for MLE messages
- **Key switch guard time** — 93% of rotation period (624 hours)

When a peer advertises a higher key sequence, the device computes
temporary keys for that sequence to decrypt the message:

```go
// Fallback: compute keys for a different sequence without switching
func (m *Manager) GetTemporaryMacKey(seq uint32) MacKey {
    dk := m.ComputeKeys(seq)
    return dk.MacKey
}
```

The guard timer prevents rapid key sequence oscillation. A device will
not switch to a new key sequence until `keySwitchGuardTime` hours have
elapsed since the last switch.

### MAC Frame Security Flow

```
  TX: payload → AES-CCM encrypt with current MAC key
       │
       │  mesh.Framer.BuildDataFrame():
       │    1. Build MAC header (FCF, addresses, aux security)
       │    2. Construct nonce from sender ExtAddress + FrameCounter
       │    3. AES-CCM Seal(nonce, payload, macHeader, tagLen=4)
       │    4. Append ciphertext + 4-byte MIC tag
       ▼
  On-air frame: [MAC header | encrypted payload | MIC-32]

  RX: received frame → AES-CCM decrypt + verify
       │
       │  mesh.DecryptFramePayload():
       │    1. Extract ciphertext and MIC tag from frame
       │    2. Reconstruct nonce from sender ExtAddress + FrameCounter
       │    3. AES-CCM Open(nonce, ciphertext, macHeader, tag)
       │    4. Verify MIC — reject if authentication fails
       ▼
  Decrypted payload delivered to upper layers
```

### Crypto Package Map

| Package          | Algorithm          | Used For                          |
|------------------|--------------------|-----------------------------------|
| `crypto/aesccm`  | AES-128-CCM        | MAC frame encryption + auth       |
| `crypto/aesecb`  | AES-128-ECB        | Block cipher primitive            |
| `crypto/hmac`    | HMAC-SHA-256       | Thread key derivation             |
| `crypto/sha256`  | SHA-256            | Hash primitive for HMAC           |
| `crypto/hkdf`    | HKDF (RFC 5869)    | Additional key derivation         |
| `crypto/ecdsa`   | ECDSA P-256        | Commissioner authentication       |
| `crypto/pbkdf2`  | PBKDF2-SHA-256     | PSKc derivation from passphrase   |

---

## Platform Abstraction

### Overview

The `platform/` package defines Go interfaces that a concrete platform
must implement. This mirrors OpenThread's `include/openthread/platform/`
C headers.

```go
// platform/platform.go

type Alarm interface {
    Start(t0, dt uint32)    // Schedule alarm at t0+dt milliseconds
    Stop()                  // Cancel pending alarm
    GetNow() uint32         // Current time in milliseconds
}

type Entropy interface {
    Fill(buf []byte) error  // Fill with crypto-quality random bytes
}

type Settings interface {
    Get(key SettingsKey, index int) ([]byte, error)
    Set(key SettingsKey, value []byte) error
    Add(key SettingsKey, value []byte) error
    Delete(key SettingsKey, index int) error
    Wipe() error
}

type Logger interface {
    Log(level LogLevel, region LogRegion, msg string)
}

type Resetter interface {
    Reset(reason ResetReason)
    GetResetReason() ResetReason
}
```

Optional interfaces:
- `AlarmMicro` — microsecond-precision timer (needed for CSL)
- `Time` — 64-bit microsecond monotonic clock

### The radio.Radio Interface

The radio interface is the most critical platform abstraction. It defines
the IEEE 802.15.4 radio hardware contract:

```go
// radio/radio.go
type Radio interface {
    // Lifecycle
    Enable() error
    Disable() error
    IsEnabled() bool
    GetState() State  // Disabled, Sleep, Receive, Transmit

    // State transitions
    Sleep() error
    Receive(channel uint8) error
    Transmit(frame *Frame) error
    GetTransmitBuffer() *Frame

    // Configuration
    GetCaps() Caps
    GetIEEEEui64() [8]byte
    SetPanID(panID uint16)
    SetExtendedAddress(addr types.ExtAddress)
    SetShortAddress(addr types.ShortAddress)
    GetTransmitPower() (int8, error)
    SetTransmitPower(power int8) error

    // Source address match (frame-pending bit in ACKs)
    EnableSrcMatch(enable bool)
    AddSrcMatchShortEntry(addr types.ShortAddress) error
    AddSrcMatchExtEntry(addr types.ExtAddress) error
    ClearSrcMatchShortEntries()
    ClearSrcMatchExtEntries()

    // Security
    SetMacKey(keyIDMode, keyID uint8, prevKey, currKey, nextKey types.KeyMaterial)
    SetMacFrameCounter(counter uint32)

    // Energy scan
    EnergyScan(channel uint8, duration uint16) error
}
```

Radio capabilities are declared via the `Caps` bitmask:

```go
const (
    CapAckTimeout      Caps = 1 << 0  // Radio handles ACK timeout
    CapEnergyScan      Caps = 1 << 1  // Hardware energy scanning
    CapTransmitRetries Caps = 1 << 2  // Radio handles TX retries
    CapCsmaBackoff     Caps = 1 << 3  // Radio handles CSMA-CA
    CapSleepToTx       Caps = 1 << 4  // TX directly from sleep
    CapTransmitSec     Caps = 1 << 5  // Radio handles TX security
    CapTransmitTiming  Caps = 1 << 6  // Scheduled transmission
    CapReceiveTiming   Caps = 1 << 7  // Scheduled reception
    CapRxOnWhenIdle    Caps = 1 << 8  // Auto sleep/receive mgmt
)
```

When a radio lacks a capability (e.g., `CapCsmaBackoff`), the SubMac layer
implements it in software.

### Callbacks Interface

The radio notifies the stack via `radio.Callbacks`:

```go
type Callbacks interface {
    HandleReceiveDone(frame *Frame, err error)
    HandleTransmitStarted(frame *Frame)
    HandleTransmitDone(frame *Frame, ackFrame *Frame, err error)
    HandleEnergyScanDone(maxRSSI int8)
}
```

### Simulation Platform

Two simulation radio implementations exist in `platform/simulation/`:

#### SimRadio (In-Process)

`SimRadio` is a lightweight simulation stub for unit testing. Multiple
SimRadio instances connect through a `Medium` that simulates the shared
RF channel:

```go
// platform/simulation/medium.go
type Medium struct {
    radios []*SimRadio
}

func (m *Medium) Broadcast(sender *SimRadio, frame *radio.Frame) int {
    // Delivers frame copy to all radios on same channel
    // in StateReceive, except the sender
}
```

Usage:

```go
medium := simulation.NewMedium()
radio1 := simulation.NewSimRadio()
radio2 := simulation.NewSimRadio()
medium.Register(radio1)
medium.Register(radio2)
```

#### UDPSimRadio (OpenThread Interop)

`UDPSimRadio` implements the same UDP multicast protocol used by
OpenThread's simulation platform, enabling gothread nodes to communicate
with OT nodes in the same simulation:

```go
// platform/simulation/udpradio.go
type UDPSimRadio struct {
    nodeID   uint16
    portBase uint16  // default: 9000
    txConn   *net.UDPConn  // bound to 127.0.0.1:portBase+nodeID
    rxFd     int           // raw socket for multicast receive
}
```

- **TX socket**: binds to `127.0.0.1:{portBase+nodeID}`
- **RX socket**: joins multicast group `224.0.0.116` on loopback
- **Wire format**: compatible with OpenThread's simulation frame format
- **CRC**: frames include CRC-16 for integrity

The RX socket enables both `SO_REUSEADDR` and `SO_REUSEPORT` so simulation
radios can share the multicast port. Socket setup errors are returned by
`Start()`, which closes any sockets opened during a failed start. Linux
(amd64 and arm64) and macOS use their native Unix socket option constants
without changing the loopback multicast interface or wire format.

This enables mixed simulations where gothread and OpenThread nodes form
a single Thread mesh network.

### Dependency Injection

Platform dependencies are injected via `instance.Config`:

```go
type Config struct {
    Alarm    platform.Alarm
    Entropy  platform.Entropy
    Settings platform.Settings
    Logger   platform.Logger
    Radio    radio.Radio

    ParentPriority   uint8
    SEDBufferSize    uint16
    SEDDatagramCount uint8
}

inst := instance.New(config)
```

---

## Package Map

### Core Infrastructure

| Package             | Role                                              |
|---------------------|---------------------------------------------------|
| `instance`          | Central coordinator, event loop, module wiring     |
| `common/message`    | Shared message buffer pool                        |
| `common/notifier`   | Protocol-level event bus                          |
| `common/settings`   | Settings driver abstraction                       |
| `common/log`        | Logging utilities                                 |
| `errors`            | Shared error types (`ErrParse`, `ErrNoBufs`, etc.)|
| `encoding`          | Big/little-endian read/write helpers              |
| `tlv`               | TLV (Type-Length-Value) parsing/building           |
| `checksum`          | Internet checksum (RFC 1071)                      |
| `crc`               | CRC-16 (used by simulation radio)                 |

### Platform & Radio

| Package                  | Role                                       |
|--------------------------|--------------------------------------------|
| `platform`               | Platform interfaces (Alarm, Entropy, etc.) |
| `platform/simulation`    | SimRadio, UDPSimRadio, Medium              |
| `radio`                  | Radio interface, Frame, State, Caps        |
| `radio/ble`              | BLE secure transport                       |
| `radio/trel`             | Thread Radio Encapsulation Link            |
| `radio/maxpower`         | TX power calibration tables                |

### MAC Layer

| Package           | Role                                            |
|-------------------|-------------------------------------------------|
| `mac`             | IEEE 802.15.4 MAC (scan, beacon, TX scheduling) |
| `mac/submac`      | Sub-MAC: CSMA-CA, retries, energy scan          |
| `mac/types`       | ExtAddress, ShortAddress, KeyMaterial, PanId     |
| `mac/frame`       | Frame parsing utilities                         |
| `mac/filter`      | Address allowlist/denylist                       |
| `mac/csl`         | Coordinated Sampled Listening scheduler          |
| `mac/channelmask` | Channel mask manipulation                       |
| `mac/links`       | Multi-radio link manager                        |
| `mac/ie`          | Information Elements                            |
| `mac/datapoll`    | Data poll handler + sender                      |
| `mac/raw`         | Raw link-layer frame access                     |
| `mac/wakeup`      | Wake-up TX scheduling                           |

### Thread Protocol

| Package                | Role                                          |
|------------------------|-----------------------------------------------|
| `thread/mle`           | Mesh Link Establishment (60+ files)           |
| `thread/routing`       | RouterTable, ChildTable, NeighborTable        |
| `thread/key`           | Key manager, key derivation, security policy  |
| `thread/mesh`          | Mesh forwarding, Framer, 802.15.4 frame build |
| `thread/lowpan`        | 6LoWPAN IPHC/NHC compression (RFC 6282)       |
| `thread/netdata`       | Network Data (leader, local, publisher)       |
| `thread/tmf`           | TMF CoAP agent + services                    |
| `thread/announce`      | MLE Announce sender/handler                   |
| `thread/discover`      | Thread network discovery scanner              |
| `thread/indirect`      | Indirect TX to sleepy end devices             |
| `thread/supervision`   | Child supervision, data poll sender/handler   |
| `thread/addrresolver`  | EID-to-RLOC16 address resolution              |
| `thread/bbr`           | BBR DUA + MLR managers                        |
| `thread/linkmetrics`   | Link Metrics (subject + initiator)            |
| `thread/mgmt`          | Energy scan + PAN ID query servers            |
| `thread/diag`          | Network diagnostics client + server           |
| `thread/timesync`      | Network time synchronization                  |
| `thread/radioselector` | Multi-radio selection policy                  |
| `thread/srcmatch`      | Source address match table management         |
| `thread/peer`          | Peer device table                             |
| `thread/tlvs`          | Thread-specific TLV types                     |
| `thread/vendor`        | Vendor-specific TLV support                   |
| `thread/mlr`           | Multicast Listener Registration               |
| `thread/netif`         | Thread network interface helpers              |
| `thread/link`          | Link quality tracking                         |

### Network Layer

| Package           | Role                                           |
|-------------------|-------------------------------------------------|
| `net/ip6`         | IPv6 header, address types, network interface   |
| `net/udp`         | UDP socket management                          |
| `net/coap`        | CoAP message exchange engine                   |
| `net/coaps`       | CoAP over DTLS (secure CoAP)                  |
| `net/icmp6`       | ICMPv6 echo + error handling                   |
| `net/dhcp6`       | DHCPv6 client + server                         |
| `net/tcp`         | TCP socket support                             |
| `net/dns`         | DNS client + DSO                               |
| `net/dnsdso`      | DNS Stateful Operations                        |
| `net/dnssd`       | DNS-SD service module                          |
| `net/dnssdserver` | DNS-SD query server                            |
| `net/mdns`        | mDNS core                                      |
| `net/slaac`       | SLAAC address generation                       |
| `net/mpl`         | Multicast Protocol for LLNs (Trickle)          |
| `net/nat64`       | NAT64 translator                               |
| `net/nd6`         | Neighbor Discovery types                       |
| `net/ndagent`     | ND proxy agent                                 |
| `net/netif`       | Network interface abstractions                 |
| `net/srp`         | SRP client + server                            |
| `net/srpadv`      | SRP Advertising Proxy                          |
| `net/sntp`        | SNTP time client                               |
| `net/socket`      | Socket abstractions                            |
| `net/ip4`         | IPv4 types (for NAT64)                         |

### Application Layer

| Package                | Role                                       |
|------------------------|--------------------------------------------|
| `meshcop`              | MeshCoP: Commissioner, Joiner, Datasets    |
| `meshcop/border`       | Border Agent, Ephemeral Key, TXT data      |
| `meshcop/dtls`         | DTLS session management                    |
| `meshcop/seeker`       | MeshCoP network seeker                     |
| `meshcop/tcat`         | BLE-based TCAT commissioning agent         |
| `backbone`             | Backbone Router (Leader, Local, Manager)   |
| `border`               | Border Router infra (InfraIf, RxRaTracker) |
| `border/router`        | RoutingManager, OMR, OnLink prefix         |
| `border/dhcp6pd`       | DHCPv6 Prefix Delegation client            |
| `border/tracker`       | Border router tracker                      |
| `border/multiail`      | Multi-AIL detector                         |
| `diags`                | Factory diagnostics                        |
| `utils`                | ChannelMonitor, JamDetector, PingSender, etc.|

### Cryptography

| Package          | Role                                          |
|------------------|-----------------------------------------------|
| `crypto/aesccm`  | AES-128-CCM authenticated encryption          |
| `crypto/aesecb`  | AES-128-ECB block cipher                      |
| `crypto/hmac`    | HMAC-SHA-256                                  |
| `crypto/sha256`  | SHA-256 hash                                  |
| `crypto/hkdf`    | HKDF key derivation (RFC 5869)                |
| `crypto/ecdsa`   | ECDSA P-256 signatures                        |
| `crypto/pbkdf2`  | PBKDF2-SHA-256 password derivation            |

### Commands

| Package         | Role                                           |
|-----------------|-------------------------------------------------|
| `cmd/gothread`  | Main CLI entry point                            |

---

## Key Design Decisions

### 1. Single-Goroutine Event Loop

All protocol logic runs on one goroutine, matching OpenThread's
single-threaded `Tasklet` model. This avoids data races between modules
without requiring fine-grained locking. External callers post closures to
`taskCh` which are executed sequentially on the event loop.

### 2. Interface-Based Platform Abstraction

Instead of OpenThread's `otPlat*` C function pointers, gothread uses Go
interfaces (`radio.Radio`, `platform.Alarm`, etc.). This enables:
- Compile-time type safety
- Easy test doubles (SimRadio)
- OpenThread interop via UDPSimRadio

### 3. Standard-Library Protocol Stack

All cryptographic primitives are implemented in-tree using the Go standard
library. The module's only external dependency is `golang.org/x/sys`, used
for Unix socket constants by the UDP simulation radio, which is excluded
from TinyGo builds.

### 4. Adapter Pattern for Module Isolation

Packages cannot import each other in cycles. The `instance/adapters.go`
file provides ~40 adapter types that bridge module interfaces. This keeps
packages independently testable while allowing the Instance to wire them
together.

### 5. Structural Port, Idiomatic Go

The port preserves OpenThread's module boundaries and naming but uses Go
idioms: exported types, error returns (not error codes), interfaces
instead of virtual methods, and goroutine-safe channel communication.

### 6. Config-Driven Construction

`instance.New(config)` takes a `Config` struct with all platform
dependencies. The `wireModules()` method creates and connects 80+ module
instances in a deterministic order (Tier 1 → 2 → 3), making the
construction sequence explicit and debuggable.
