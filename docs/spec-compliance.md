# Specification & Compliance Sheet

> **gothread** — A pure Go implementation of the Thread 1.4.0 networking protocol  
> Module: `github.com/hilli/gothread`  
> Reference commit: `openthread/openthread@3f11074f1e188bd84d7d530da271ce5bc66bc3ec`

Status indicators:

| Icon | Meaning |
|------|---------|
| ✅ | Implemented — real logic with protocol-compliant behavior |
| ⚠️ | Partial/Stubbed — types or skeleton present, incomplete logic |
| 🔲 | Not yet implemented |

---

## 1. Thread 1.4.0 Feature Matrix

### 1.1 Mesh Link Establishment (MLE)

| Feature | Status | Package | Notes |
|---------|--------|---------|-------|
| Device roles (Leader, Router, Child) | ✅ | `thread/mle/` | `RoleLeader`, `RoleRouter`, `RoleChild`, `RoleDetached`, `RoleDisabled` |
| REED (Router-Eligible End Device) | ✅ | `thread/mle/` | Determined by `DeviceMode` flags (`IsFullThreadDevice()`) |
| Sleepy End Device (SED) | ✅ | `thread/mle/` | Determined by `IsRxOnWhenIdle()` / `IsMinimalEndDevice()` |
| Parent Request / Response | ✅ | `thread/mle/` | Full handler with scan mask, challenge, delayed responses |
| Child ID Request / Response | ✅ | `thread/mle/` | RLOC16 allocation, challenge-response validation |
| Advertisement handling | ✅ | `thread/mle/` | Partition merging, leader changes, data version tracking |
| MLE Discovery | ✅ | `thread/discover/` | Active scan with filtering |
| Announce (channel change) | ✅ | `thread/announce/` | Announce Sender & Begin Server with channel iteration |
| Link Metrics | ✅ | `thread/linkmetrics/` | Link metrics tracking with typed metrics |
| Time Synchronization | ✅ | `thread/timesync/` | Time sync IE support |

### 1.2 MAC Layer (IEEE 802.15.4)

| Feature | Status | Package | Notes |
|---------|--------|---------|-------|
| MAC operations (enable/disable/scan/tx) | ✅ | `mac/` | 7 operation types, active/energy scanning, beacon handling |
| Frame parsing & building | ✅ | `mac/frame/` | 30+ methods; FCF, addressing, security headers |
| Data polling (SED ↔ parent) | ✅ | `mac/datapoll/` | Handler (parent) + Sender (child), 4 poll modes |
| CSL (Coordinated Sampled Listening) | ✅ | `mac/csl/` | Scheduler with delay calculation per CSL spec |
| Source address matching | ✅ | `mac/` + `thread/srcmatch/` | Frame-pending bit management for ACKs |
| SubMac abstraction | ✅ | `mac/submac/` | Radio/MAC split abstraction |
| Channel masking | ✅ | `mac/channelmask/` | Channel mask operations |
| MAC filtering | ✅ | `mac/filter/` | Address-based frame filtering |
| Raw link access | ✅ | `mac/raw/` | Raw IEEE 802.15.4 frame access |
| Information Elements (IEs) | ✅ | `mac/ie/` | CSL IE, TimeSync IE, Link Metrics IE, Vendor IE |
| Wake-up frames | ✅ | `mac/wakeup/` | Wake-up radio support |

### 1.3 Mesh Forwarding

| Feature | Status | Package | Notes |
|---------|--------|---------|-------|
| Mesh header construction/parsing | ✅ | `thread/mesh/` | `BuildMeshHeader`, `ParseMeshHeader` |
| Direct/indirect TX queues | ✅ | `thread/mesh/` | Queue management with priority and eviction |
| 6LoWPAN fragmentation/reassembly | ✅ | `thread/mesh/` | Timeout tracking for fragment reassembly |
| Indirect transmission | ✅ | `thread/indirect/` | Indirect TX with source match controller |
| Routing table | ✅ | `thread/routing/` | Router/neighbor tables, path cost calculation |
| Child supervision | ✅ | `thread/supervision/` | Supervision timer & data poll management |

### 1.4 6LoWPAN

| Feature | Status | Package | Notes |
|---------|--------|---------|-------|
| IPHC compression | ✅ | `thread/lowpan/` | Stateful IPHC with context support (RFC 6282) |
| IPHC decompression | ✅ | `thread/lowpan/` | Full address reconstruction from compressed headers |
| NHC UDP compression | ✅ | `thread/lowpan/` | UDP header compression/decompression |
| Fragment headers | ✅ | `thread/lowpan/` | Fragment header parsing & construction |
| Context-based compression | ✅ | `thread/lowpan/` | Context ID for mesh-local prefix compression |

### 1.5 Network Data

| Feature | Status | Package | Notes |
|---------|--------|---------|-------|
| On-mesh prefixes | ✅ | `thread/netdata/` | TLV encoding/decoding, border router entries |
| External routes | ✅ | `thread/netdata/` | HasRouteEntry encoding with preference flags |
| Services | ✅ | `thread/netdata/` | Service TLV handling |
| Leader network data | ✅ | `thread/netdata/` | Version tracking, router verification |
| Context IDs | ✅ | `thread/netdata/` | Context ID management for 6LoWPAN |
| Commissioning data | ✅ | `thread/netdata/` | Commissioning data TLVs |

### 1.6 Commissioning (MeshCoP)

| Feature | Status | Package | Notes |
|---------|--------|---------|-------|
| Commissioner (petition/keep-alive) | ✅ | `meshcop/` | State machine: Disabled → Petition → Active |
| Joiner (scan/DTLS/finalize) | ✅ | `meshcop/` | Full state machine: Idle → Discover → Connect → Connected → Entrust → Joined |
| Joiner Router | ✅ | `meshcop/` | Joiner router relay |
| Commissioner Leader | ✅ | `meshcop/` | Leader-side commissioner management |
| Datasets (Active/Pending) | ✅ | `meshcop/` | Binary serialization, all credential fields |
| Dataset Manager | ✅ | `meshcop/` | Dataset update and persistence |
| Dataset Updater | ✅ | `meshcop/` | Pending dataset application |
| DTLS 1.2 transport | ✅ | `meshcop/dtls/` | EC-JPAKE, PSK auth, session state machine |
| Steering data (Bloom filter) | ✅ | `meshcop/` | Joiner steering data |
| MeshCoP TLVs | ✅ | `meshcop/` | Full TLV set |
| Timestamps | ✅ | `meshcop/` | Dataset timestamps |
| TCAT (Thread Commissioning) | ✅ | `meshcop/tcat/` | Thread Commissioning over Authenticated TLS |
| Seeker | ✅ | `meshcop/seeker/` | Commissioner candidate discovery |
| Border agent | ✅ | `meshcop/border/` | Border agent commissioning |

### 1.7 Key Management

| Feature | Status | Package | Notes |
|---------|--------|---------|-------|
| Network key management | ✅ | `thread/key/` | Network key storage and distribution |
| Key rotation | ✅ | `thread/key/` | `SetCurrentKeySequence()` with guard timer |
| MAC/MLE key derivation | ✅ | `thread/key/` | `ComputeKeys()` for MAC and MLE keys |
| Frame counter management | ✅ | `thread/key/` | MAC/MLE frame counters with rollover protection |
| PSKc handling | ✅ | `thread/key/` | Pre-Shared Key for Commissioner |
| Key switch guard | ✅ | `thread/key/` | Temporal guard enforcement per Thread spec |

### 1.8 Address Resolution

| Feature | Status | Package | Notes |
|---------|--------|---------|-------|
| Address query/notification | ✅ | `thread/addrresolver/` | Query → response → cached state machine |
| Address cache | ✅ | `thread/addrresolver/` | Cache with snooped entries and eviction |
| Retry with exponential backoff | ✅ | `thread/addrresolver/` | RetryQuery state with backoff |
| EID-to-RLOC mapping | ✅ | `thread/addrresolver/` | Mesh-local IID storage and lookup |

### 1.9 Multicast

| Feature | Status | Package | Notes |
|---------|--------|---------|-------|
| MPL forwarder | ✅ | `net/mpl/` | Full Trickle timer, seed ID, retransmission (RFC 7731) |
| Multicast Listener Registration | ⚠️ | `thread/mlr/` + `thread/bbr/` | Types/constants in `mlr/`; actual logic in `bbr/mlr_manager.go` |

### 1.10 Border Router Features

| Feature | Status | Package | Notes |
|---------|--------|---------|-------|
| Border Router (RA, OMR, on-link) | ✅ | `border/router/` | RA builder, OMR/on-link prefix management, route publishing |
| Infrastructure interface | ✅ | `border/` | InfraIf abstraction with RA tracker |
| Backbone Router (BBR) | ⚠️ | `thread/bbr/` | DUA manager implemented; backbone integration partial |
| DUA (Domain Unicast Address) | ✅ | `thread/bbr/` | State machine: Idle → ToRegister → Registering → Registered |
| MLR Manager | ✅ | `thread/bbr/` | Multicast listener state tracking (max 15 entries) |
| NAT64 translator | ✅ | `net/nat64/` | IPv6 ↔ IPv4 translation (RFC 6145/6146), session tracking |
| DHCPv6 Prefix Delegation | ✅ | `border/dhcp6pd/` | PD client for border routers |
| Multi-AiL (Anycast-based Infra Link) | ✅ | `border/multiail/` | Multiple infrastructure link support |

### 1.11 DNS-SD / SRP

| Feature | Status | Package | Notes |
|---------|--------|---------|-------|
| DNS client | ✅ | `net/dns/` | Query types: address, browse, SRV+TXT; retry, CNAME following |
| DNS-SD abstractions | ⚠️ | `net/dnssd/` | Type definitions and state tracking; mDNS transport delegated to platform |
| DNS-SD Server | ✅ | `net/dnssdserver/` | Server-side DNS-SD handling |
| DNS-DSO (Stateful Operations) | ✅ | `net/dnsdso/` | DNS Stateful Operations support |
| SRP client | ✅ | `net/srp/` | ECDSA/SHA-256 auth, lease management, auto-renewal with jitter |
| SRP advertising proxy | ✅ | `net/srpadv/` | SRP advertising proxy |
| mDNS | ✅ | `net/mdns/` | Message handling and caching |

### 1.12 Thread Management Framework (TMF)

| Feature | Status | Package | Notes |
|---------|--------|---------|-------|
| TMF Agent | ✅ | `thread/tmf/` | CoAP-based management agent |
| TMF Client/Server | ✅ | `thread/tmf/` | Client and server implementations |
| TMF Leader | ✅ | `thread/tmf/` | Leader-specific TMF resources |
| Commissioner data | ✅ | `thread/tmf/` | Commissioner data handling |
| Server data | ✅ | `thread/tmf/` | Server data handling |

---

## 2. IEEE 802.15.4 Compliance

### 2.1 Frame Types

| Frame Type | Value | Status |
|------------|-------|--------|
| Beacon | `0x00` | ✅ |
| Data | `0x01` | ✅ |
| Acknowledgement | `0x02` | ✅ |
| MAC Command | `0x03` | ✅ |
| Multipurpose | `0x05` | ✅ |

### 2.2 Frame Versions

| Version | Value | Status |
|---------|-------|--------|
| IEEE 802.15.4-2003 | `0x0000` | ✅ |
| IEEE 802.15.4-2006 | `0x1000` | ✅ |
| IEEE 802.15.4-2015 | `0x2000` | ✅ |

### 2.3 Security Levels

| Security Level | Value | MIC Size | Encryption | Status |
|----------------|-------|----------|------------|--------|
| None | `0` | — | No | ✅ |
| MIC-32 | `1` | 4 bytes | No | ✅ |
| MIC-64 | `2` | 8 bytes | No | ✅ |
| MIC-128 | `3` | 16 bytes | No | ✅ |
| ENC | `4` | — | Yes | ✅ |
| ENC-MIC-32 | `5` | 4 bytes | Yes | ✅ |
| ENC-MIC-64 | `6` | 8 bytes | Yes | ✅ |
| ENC-MIC-128 | `7` | 16 bytes | Yes | ✅ |

### 2.4 Addressing Modes

| Mode | Status | Notes |
|------|--------|-------|
| None (no address) | ✅ | FCF address mode 0 |
| Short (16-bit) | ✅ | FCF address mode 2 |
| Extended (64-bit EUI-64) | ✅ | FCF address mode 3 |

### 2.5 Key Identifier Modes

| Key ID Mode | Size | Status |
|-------------|------|--------|
| Mode 0 — implicit | 0 bytes | ✅ |
| Mode 1 — 1-byte key index | 1 byte | ✅ |
| Mode 2 — 4-byte source + index | 5 bytes | ✅ |
| Mode 3 — 8-byte source + index | 9 bytes | ✅ |

### 2.6 Information Elements

| IE Type | ID | Status |
|---------|----|--------|
| CSL (Coordinated Sampled Listening) | `0x1A` | ✅ |
| Time Synchronization (Thread) | `0x1B` | ✅ |
| Vendor-Specific | `0x00` | ✅ |
| Header Termination 1 (payload follows) | `0x7E` | ✅ |
| Header Termination 2 (no payload) | `0x7F` | ✅ |
| Thread Link Metrics (vendor sub-IE) | `0x00` | ✅ |

---

## 3. RFC Compliance

| RFC | Title | Status | Package |
|-----|-------|--------|---------|
| RFC 6282 | 6LoWPAN IPHC Compression | ✅ | `thread/lowpan/` |
| RFC 4944 | 6LoWPAN Transmission over IEEE 802.15.4 | ✅ | `thread/lowpan/`, `thread/mesh/` |
| RFC 7252 | CoAP (Constrained Application Protocol) | ✅ | `net/coap/` |
| RFC 7390 | CoAP Group Communication | ✅ | `net/coap/` |
| RFC 7731 | MPL (Multicast Protocol for Low-Power) | ✅ | `net/mpl/` |
| RFC 4861 | IPv6 Neighbor Discovery | ✅ | `net/nd6/` |
| RFC 8106 | IPv6 RA DNS Options (RDNSS/DNSSL) | ✅ | `net/nd6/` |
| RFC 5175 | IPv6 RA Flags Options Extension | ✅ | `net/nd6/` |
| RFC 6347 | DTLS 1.2 | ✅ | `meshcop/dtls/` |
| RFC 4493 | AES-CMAC | ✅ | `crypto/pbkdf2/` |
| RFC 4615 | AES-CMAC-PRF-128 | ✅ | `crypto/pbkdf2/` |
| RFC 5869 | HKDF (HMAC-based Key Derivation) | ✅ | `crypto/hkdf/` |
| RFC 2104 | HMAC | ✅ | `crypto/hmac/` |
| RFC 6145 | IP/ICMP Translation (IPv4 ↔ IPv6) | ✅ | `net/nat64/` |
| RFC 6146 | Stateful NAT64 | ✅ | `net/nat64/` |
| RFC 7217 | Semantically Opaque IIDs (SLAAC) | ✅ | `net/slaac/` |
| RFC 4862 | IPv6 SLAAC | ✅ | `net/slaac/` |
| RFC 2136 | DNS Dynamic Updates | ✅ | `net/srp/` |
| RFC 2931 | DNS SIG(0) Authentication | ✅ | `net/srp/` |
| RFC 6763 | DNS-Based Service Discovery | ⚠️ | `net/dnssd/` |
| RFC 8415 | DHCPv6 | ✅ | `net/dhcp6/` |
| RFC 4443 | ICMPv6 | ✅ | `net/icmp6/` |
| RFC 793 | TCP | 🔲 | `net/tcp/` — stub only |
| RFC 768 | UDP | ✅ | `net/udp/` |
| RFC 4291 | IPv6 Addressing Architecture | ✅ | `net/ip6/` |
| RFC 5765 | EC-JPAKE | ✅ | `meshcop/dtls/` |
| RFC 6234 | SHA-256 | ✅ | `crypto/sha256/` |
| RFC 5116 | AES-CCM (AEAD) | ✅ | `crypto/aesccm/` |
| RFC 4492 | ECC for TLS (ECDSA) | ✅ | `crypto/ecdsa/` |
| RFC 2898 | PBKDF2 | ✅ | `crypto/pbkdf2/` |
| RFC 5905 | NTP/SNTP | ✅ | `net/sntp/` |
| RFC 6762 | Multicast DNS | ✅ | `net/mdns/` |

---

## 4. Security Features

### 4.1 Cryptographic Primitives

| Algorithm | Status | Package | Notes |
|-----------|--------|---------|-------|
| AES-128-ECB | ✅ | `crypto/aesecb/` | Single-block encryption via Go `crypto/aes` |
| AES-128-CCM | ✅ | `crypto/aesccm/` | Authenticated encryption: CBC-MAC + CTR mode, constant-time tag verify |
| AES-CMAC (RFC 4493) | ✅ | `crypto/pbkdf2/` | Subkey generation, block processing with padding |
| SHA-256 | ✅ | `crypto/sha256/` | Incremental API (`Start`/`Update`/`Finish`) via Go `crypto/sha256` |
| HMAC-SHA-256 | ✅ | `crypto/hmac/` | Incremental API via Go `crypto/hmac` |
| HKDF-SHA-256 (RFC 5869) | ✅ | `crypto/hkdf/` | Extract + Expand phases via Go `crypto/hkdf` |
| PBKDF2-AES-CMAC-PRF-128 | ✅ | `crypto/pbkdf2/` | Full PBKDF2-F computation (RFC 4615) |
| ECDSA P-256 | ✅ | `crypto/ecdsa/` | Key generation, signing, verification via Go `crypto/ecdsa` |

### 4.2 Thread Security Functions

| Function | Status | Package | Notes |
|----------|--------|---------|-------|
| Network key derivation | ✅ | `thread/key/` | MAC/MLE key derivation via `ComputeKeys()` |
| Key rotation with guard timer | ✅ | `thread/key/` | Temporal guard enforcement per Thread spec |
| MAC frame counters | ✅ | `thread/key/` | Rollover protection, stored counters |
| MLE frame counters | ✅ | `thread/key/` | Separate MLE counter management |
| PSKc (Commissioner credential) | ✅ | `thread/key/` | Pre-Shared Key for Commissioner |
| MAC-layer encryption (AES-CCM-128) | ✅ | `mac/frame/` + `crypto/aesccm/` | Security level 5 (ENC-MIC-32) default for Thread |
| DTLS 1.2 with EC-JPAKE | ✅ | `meshcop/dtls/` | Commissioning handshake security |
| Joiner credential (PSKd) | ✅ | `meshcop/` | Joiner authentication via DTLS |

### 4.3 Checksums & Integrity

| Feature | Status | Package | Notes |
|---------|--------|---------|-------|
| CRC computation | ✅ | `crc/` | CRC calculation for frame integrity |
| Internet checksum | ✅ | `checksum/` | IPv6/UDP/TCP checksum computation |
| Verhoeff check digit | ✅ | `checksum/` | Joiner credential validation |

---

## 5. Radio Capabilities

The `radio.Radio` interface (`radio/radio.go`) defines the hardware abstraction layer for IEEE 802.15.4 radio access.

### 5.1 Capability Flags (`radio.Caps`)

| Capability | Bit | Description |
|------------|-----|-------------|
| `CapAckTimeout` | `1 << 0` | Radio handles ACK timeout internally |
| `CapEnergyScan` | `1 << 1` | Hardware energy scanning support |
| `CapTransmitRetries` | `1 << 2` | TX retries with CSMA-CA |
| `CapCsmaBackoff` | `1 << 3` | CSMA backoff handled internally |
| `CapSleepToTx` | `1 << 4` | Transmit directly from sleep state |
| `CapTransmitSec` | `1 << 5` | Hardware TX security (encryption) |
| `CapTransmitTiming` | `1 << 6` | Scheduled/timed transmission |
| `CapReceiveTiming` | `1 << 7` | Scheduled/timed reception |
| `CapRxOnWhenIdle` | `1 << 8` | Auto sleep/receive management |
| `CapTransmitFramePower` | `1 << 9` | Per-frame TX power control |
| `CapAltShortAddr` | `1 << 10` | Alternate short address support |

### 5.2 Radio Interface Methods (39 total)

| Category | Methods | Count |
|----------|---------|-------|
| Lifecycle | `Enable`, `Disable`, `IsEnabled`, `GetState` | 4 |
| State transitions | `Sleep`, `Receive`, `Transmit`, `GetTransmitBuffer` | 4 |
| Configuration | `GetCaps`, `GetIEEEEui64`, `SetPanID`, `SetExtendedAddress`, `SetShortAddress`, `SetTransmitPower`, `GetTransmitPower`, `SetPromiscuous`, `GetPromiscuous`, `GetRSSI`, `GetSupportedChannelMask`, `GetPreferredChannelMask`, `GetReceiveSensitivity` | 13 |
| Source match | `EnableSrcMatch`, `Add/ClearSrcMatchShortEntry`, `Add/ClearSrcMatchExtEntry`, `ClearSrcMatchShortEntries`, `ClearSrcMatchExtEntries` | 7 |
| Security | `SetMacKey`, `SetMacFrameCounter`, `SetMacFrameCounterIfLarger` | 3 |
| Energy scan | `EnergyScan` | 1 |

### 5.3 Radio State Machine

```
StateDisabled (0) ──Enable──► StateReceive (2) ◄──Receive──┐
                                    │                       │
                                  Sleep                  Receive
                                    │                       │
                                    ▼                       │
                              StateSleep (1) ───────────────┘
                                    │
                                 Transmit
                                    │
                                    ▼
                            StateTransmit (3)
```

### 5.4 Callback Interface

| Callback | Description |
|----------|-------------|
| `HandleReceiveDone` | Frame received (with error status) |
| `HandleTransmitStarted` | Frame transmission initiated |
| `HandleTransmitDone` | Transmission complete (with ACK frame and error status) |
| `HandleEnergyScanDone` | Energy scan complete (with max RSSI) |

### 5.5 Additional Radio Interfaces

| Interface | Package | Status | Notes |
|-----------|---------|--------|-------|
| BLE secure transport | `radio/ble/` | ✅ | State machine: Disabled → Idle → Connecting → Connected |
| TREL (Thread Radio Encapsulation Link) | `radio/trel/` | ✅ | Peer/link/packet abstractions, platform UDP/DNS-SD interface |
| Max power management | `radio/maxpower/` | ✅ | Per-channel TX power limits |

---

## 6. Platform Requirements

### 6.1 Go Version

| Requirement | Value |
|-------------|-------|
| Minimum Go version | **1.25+** |
| Module path | `github.com/hilli/gothread` |

### 6.2 Dependencies

| Aspect | Status | Notes |
|--------|--------|-------|
| Pure Go | ✅ | No CGo dependency — `go.mod` has zero external dependencies |
| Standard library only | ✅ | All crypto uses Go stdlib (`crypto/aes`, `crypto/ecdsa`, `crypto/sha256`, etc.) |
| Cross-platform | ✅ | No OS-specific system calls in core packages |

### 6.3 Build & Test

```sh
task build     # Build all packages
task test      # Run all tests
task lint      # Run linter (golangci-lint)
task ci        # Run all CI checks
```

### 6.4 Platform Abstraction

| Component | Package | Notes |
|-----------|---------|-------|
| Platform interface | `platform/` | Platform detection and abstractions |
| Simulation support | `platform/simulation/` | Simulation platform for testing |
| Instance lifecycle | `instance/` | Instance wiring and adapter management |
| Diagnostics | `diags/` | Diagnostic mode for radio testing |

---

## 7. OpenThread Compatibility

### 7.1 Reference Implementation

| Property | Value |
|----------|-------|
| Upstream project | [openthread/openthread](https://github.com/openthread/openthread) |
| Reference commit | `3f11074f1e188bd84d7d530da271ce5bc66bc3ec` |
| Port approach | Idiomatic Go rewrite — not a binding or wrapper |
| License | BSD 3-Clause (same as OpenThread) |

### 7.2 Wire Compatibility

| Aspect | Status | Notes |
|--------|--------|-------|
| IEEE 802.15.4 frame format | ✅ | Byte-level compatible frame parsing/building |
| MLE message format | ✅ | TLV encoding matches OpenThread wire format |
| 6LoWPAN IPHC encoding | ✅ | RFC 6282 compliant compression |
| MeshCoP TLV encoding | ✅ | Binary-compatible dataset serialization |
| CoAP message format | ✅ | RFC 7252 compliant message structure |
| Thread TLV encoding | ✅ | Shared TLV format across thread/tmf |
| Network Data TLVs | ✅ | Compatible prefix/route/service encoding |

### 7.3 Architectural Mapping

| OpenThread (C++) | gothread (Go) | Notes |
|------------------|---------------|-------|
| `src/core/thread/mle.cpp` | `thread/mle/` | MLE roles, handlers, TLVs |
| `src/core/thread/mesh_forwarder.cpp` | `thread/mesh/` | Mesh forwarding with queues |
| `src/core/thread/lowpan.cpp` | `thread/lowpan/` | IPHC compression engine |
| `src/core/thread/network_data.cpp` | `thread/netdata/` | Network data management |
| `src/core/thread/key_manager.cpp` | `thread/key/` | Key rotation and derivation |
| `src/core/thread/address_resolver.cpp` | `thread/addrresolver/` | EID-to-RLOC cache |
| `src/core/meshcop/` | `meshcop/` | Commissioning protocol |
| `src/core/mac/mac.cpp` | `mac/` | MAC layer operations |
| `src/core/crypto/` | `crypto/` | Cryptographic primitives |
| `src/core/net/` | `net/` | Network protocols (CoAP, IP6, UDP, etc.) |
| `src/core/border_router/` | `border/` | Border router features |
| `src/core/backbone_router/` | `backbone/` + `thread/bbr/` | Backbone router |
| `include/openthread/platform/radio.h` | `radio/radio.go` | Radio HAL interface |

---

## 8. Implementation Summary

### 8.1 By Category

| Category | Implemented | Partial | Not Implemented | Total |
|----------|:-----------:|:-------:|:---------------:|:-----:|
| MLE | 10 | 0 | 0 | 10 |
| MAC Layer | 11 | 0 | 0 | 11 |
| Mesh Forwarding | 6 | 0 | 0 | 6 |
| 6LoWPAN | 5 | 0 | 0 | 5 |
| Network Data | 6 | 0 | 0 | 6 |
| Commissioning | 14 | 0 | 0 | 14 |
| Key Management | 6 | 0 | 0 | 6 |
| Address Resolution | 4 | 0 | 0 | 4 |
| Multicast | 1 | 1 | 0 | 2 |
| Border Router | 7 | 1 | 0 | 8 |
| DNS-SD / SRP | 6 | 1 | 0 | 7 |
| TMF | 5 | 0 | 0 | 5 |
| Crypto | 8 | 0 | 0 | 8 |
| Network Protocols | 10 | 0 | 1 | 11 |
| **Total** | **99** | **3** | **1** | **103** |

### 8.2 Notable Gaps

| Feature | Status | Notes |
|---------|--------|-------|
| TCP | 🔲 | Stub only — "Full TCP functionality will be implemented in a later phase" |
| BBR backbone integration | ⚠️ | DUA/MLR managers implemented; full backbone link incomplete |
| MLR types | ⚠️ | Type definitions only in `thread/mlr/`; logic lives in `thread/bbr/` |
| DNS-SD platform transport | ⚠️ | Interface definitions; mDNS transport delegated to platform layer |

### 8.3 Test Coverage

The codebase includes `*_test.go` files alongside most packages, with verified round-trip tests for compression, encryption, dataset serialization, and frame parsing. A `coverage.out` file is maintained at the repository root.

---

*Generated from codebase analysis. Last verified against module `github.com/hilli/gothread` at Go 1.25.*
