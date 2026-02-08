# gothread - Pure Go Port of OpenThread

## Project Overview

**gothread** is a pure Go implementation of the Thread 1.4.0 networking protocol, ported from [OpenThread](https://github.com/openthread/openthread) (BSD 3-Clause). It implements all Thread networking layers: IPv6, 6LoWPAN, IEEE 802.15.4 with MAC security, Mesh Link Establishment, Mesh Routing, and Border Router support.

- **Concurrency model:** Single goroutine event loop, faithful to OpenThread's cooperative scheduling model.
- **Source reference:** OpenThread `main` branch at commit `3f11074f1` (2026-02-07), Thread specification 1.4.0.
- **Language:** Go 1.25+, idiomatic Go style.
- **Build system:** Taskfile.yaml (not Makefile).
- **CI:** GitHub Actions for build, lint, and test on push.
- **Methodology:** TDD — tests written first using extracted test vectors from OpenThread's C++ test suite.

## Package Structure

```
github.com/hilli/gothread/
├── encoding/          # Big-endian/little-endian wire format helpers
├── errors/            # Thread error types (38 error codes -> sentinel errors)
├── tlv/               # TLV (Type-Length-Value) parsing/building framework
├── crc/               # CRC-16 (CCITT, ANSI) and CRC-32
├── checksum/          # Internet checksum (RFC 1071)
├── crypto/
│   ├── aesccm/        # AES-128-CCM authenticated encryption
│   ├── aesecb/        # AES-128-ECB block cipher
│   ├── hmac/          # HMAC-SHA-256
│   ├── hkdf/          # HKDF-SHA-256 (RFC 5869)
│   ├── ecdsa/         # ECDSA P-256 signing/verification
│   └── pbkdf2/        # PBKDF2 with AES-CMAC-PRF-128
├── mac/
│   ├── types/         # ExtAddress, ShortAddress, PanId, Key, etc.
│   ├── frame/         # IEEE 802.15.4 frame parsing/building
│   ├── submac/        # Sub-MAC: CSMA/CA, retransmissions, energy scan
│   └── mac.go         # Full MAC layer state machine
├── net/
│   ├── ip6/           # IPv6 addresses, headers, packet processing
│   ├── udp/           # UDP sockets
│   ├── tcp/           # TCP
│   ├── icmp6/         # ICMPv6
│   ├── dns/           # DNS types, name encoding, client
│   ├── srp/           # SRP client/server
│   ├── coap/          # CoAP message/client/server
│   ├── coaps/         # CoAP over DTLS
│   ├── nat64/         # NAT64 translator
│   └── dhcp6/         # DHCPv6
├── thread/
│   ├── key/           # Key manager (MAC/MLE key derivation, rotation)
│   ├── lowpan/        # 6LoWPAN IPHC compression/decompression
│   ├── mle/           # Mesh Link Establishment
│   ├── mesh/          # Mesh forwarding
│   ├── netdata/       # Thread Network Data
│   ├── routing/       # Router/child/neighbor tables, address resolver
│   └── link/          # Link quality, link metrics
├── meshcop/
│   ├── dataset/       # Operational Dataset management
│   ├── commissioner/  # Commissioner role
│   ├── joiner/        # Joiner role
│   ├── dtls/          # DTLS transport
│   └── border/        # Border Agent
├── radio/             # Radio interface (Go interface for platform impl)
├── platform/          # Platform abstraction interfaces (timers, storage, entropy)
├── border/
│   ├── router/        # Border routing manager
│   └── backbone/      # Backbone Router
├── instance/          # Instance struct (owns all modules, event loop)
├── cli/               # CLI interface
├── cmd/
│   └── gothread/      # Main binary
├── docs/
│   └── plans/         # Design documents
├── .github/
│   └── workflows/     # CI: build, lint, test
├── Taskfile.yaml      # Build tasks
├── .golangci.yml      # Linter config
├── go.mod
├── LICENSE
└── README.md
```

### Key Design Decisions

- Flat-ish packages, not deeply nested — idiomatic Go.
- `platform/` and `radio/` are interfaces only — implementations are separate.
- Many C++ utilities (`LinkedList`, `Pool`, `Message`) map to Go builtins (`[]byte`, `sync.Pool`, slices).
- The `Instance` struct uses composition — holds all modules as fields.
- Single goroutine event loop; OpenThread's tasklets/timers map to Go's `time.Timer` + channels.
- Conditional compilation (`#if OPENTHREAD_CONFIG_*`) maps to Go build tags or interface-based pluggability.

## Concurrency Model

OpenThread is single-threaded and cooperative (tasklets + timers, no concurrent access to shared state). The Go port preserves this:

- **Single goroutine event loop** — one main goroutine processes all events.
- Other goroutines communicate only via channels.
- This preserves behavioral equivalence with the C++ reference — critical for correctness verification.
- Selective concurrency can be introduced later (crypto, DNS) once the port is complete and tested.

## Implementation Phases

### Phase 1: Foundation (all parallelizable)

5 packages, zero internal dependencies.

| Package | What it ports | Est. size | Test vectors |
|---------|--------------|-----------|-------------|
| `errors/` | 38 `otError` codes -> Go sentinel errors | ~100 LOC | Trivial |
| `encoding/` | Big-endian read/write helpers | ~150 LOC | Trivial |
| `crc/` | CRC-16 CCITT, CRC-16 ANSI, CRC-32 | ~150 LOC | 3 algos x 3 datasets |
| `checksum/` | Internet checksum (RFC 1071) | ~100 LOC | RFC 1071 + ICMP vectors |
| `tlv/` | TLV + ExtendedTLV parse/build | ~300 LOC | MLE/MeshCoP test data |

### Phase 2: Crypto (all parallelizable)

6 packages wrapping Go stdlib crypto.

| Package | What it ports | Wraps |
|---------|--------------|-------|
| `crypto/aesecb/` | AES-128-ECB block cipher | `crypto/aes` |
| `crypto/aesccm/` | AES-128-CCM authenticated encryption | `crypto/aes` + `crypto/cipher` |
| `crypto/hmac/` | HMAC-SHA-256 | `crypto/hmac` + `crypto/sha256` |
| `crypto/hkdf/` | HKDF-SHA-256 (RFC 5869) | `golang.org/x/crypto/hkdf` |
| `crypto/ecdsa/` | ECDSA P-256 sign/verify | `crypto/ecdsa` + `crypto/elliptic` |
| `crypto/pbkdf2/` | PBKDF2 with AES-CMAC-PRF-128 | Custom |

### Phase 3: Types & Addresses (all parallelizable)

Depends on: `encoding/`, `errors/`.

| Package | What it ports | Test vectors |
|---------|--------------|-------------|
| `mac/types/` | ExtAddress, ShortAddress, PanId, Address, Key, KeyMaterial | Address formatting |
| `net/ip6/` (addresses) | Address, Prefix, NetworkPrefix, InterfaceIdentifier, parsing | 15+ IPv6, 6+ IPv4, 7 NAT64 |
| `net/dns/` (names) | DNS name encoding, parsing, label matching | 4+ encoding, subdomain matching |

### Phase 4: Frame & Protocol Types (all parallelizable)

Depends on: Phase 3 + `crypto/`, `tlv/`, `crc/`.

| Package | What it ports | Complexity |
|---------|--------------|------------|
| `mac/frame/` | IEEE 802.15.4 frame parsing/building | **High** — bit-level parsing |
| `thread/lowpan/` | 6LoWPAN IPHC compression/decompression | **High** — bit-level |
| `net/ip6/` (headers) | IPv6/UDP/TCP header types, extension headers | Medium |
| `net/coap/` (messages) | CoAP message parsing/building | Medium |

### Phase 5: Platform Interfaces & Runtime

Depends on: Phase 1-2.

| Package | What it provides |
|---------|-----------------|
| `platform/` | Go interfaces: Timer, Alarm, Storage, Entropy, Logger |
| `radio/` | Go interface: Radio (transmit, receive, channel, power, state machine) |
| `instance/` (skeleton) | Instance struct, event loop, module wiring |

### Phase 6: MAC Layer

Sequential: `mac/submac/` then `mac/` (full).

Depends on: Phase 4 + 5.

### Phase 7: Networking Stack

`net/ip6/` (full) first, then `net/udp/`, `net/icmp6/`, `net/tcp/` in parallel.

Depends on: Phase 6.

### Phase 8: Thread Protocol Core

`thread/key/` first, then remaining packages in parallel where possible.

Depends on: Phase 7.

| Package | What it ports |
|---------|--------------|
| `thread/key/` | Key manager — MAC/MLE key derivation, rotation |
| `thread/link/` | Link quality tracking, RSS averaging |
| `thread/mle/` | Mesh Link Establishment — attach, roles, parent selection |
| `thread/mesh/` | Mesh forwarding (bridge between IP and MAC) |
| `thread/netdata/` | Thread Network Data TLVs, leader/local management |
| `thread/routing/` | Router table, child table, neighbor table, address resolver |

### Phase 9: Commissioning & Services (mostly parallel)

Depends on: Phase 8.

| Package | What it ports |
|---------|--------------|
| `meshcop/dataset/` | Operational Dataset (active/pending) |
| `meshcop/dtls/` | DTLS transport |
| `meshcop/commissioner/` | Commissioner role |
| `meshcop/joiner/` | Joiner role |
| `meshcop/border/` | Border Agent |
| `net/srp/` | SRP client/server |
| `net/dns/` (full) | DNS client, DNS-SD server |
| `net/coap/` (full) | CoAP client/server engine |
| `net/coaps/` | CoAP over DTLS |

### Phase 10: Border Router, Utilities & CLI

Depends on: Phase 9.

| Package | What it ports |
|---------|--------------|
| `border/router/` | Border routing manager, RA, prefix discovery |
| `border/backbone/` | Backbone Router, multicast listeners, ND proxy |
| `net/nat64/` | NAT64 translator |
| `net/dhcp6/` | DHCPv6 client/server |
| `cli/` | CLI interface |
| `cmd/gothread/` | Main binary |

## Parallelization Strategy

| Phase | Packages | Parallel agents |
|-------|----------|----------------|
| 1 | 5 | 5 (all independent) |
| 2 | 6 | 6 (all independent) |
| 3 | 3 | 3 (all independent) |
| 4 | 4 | 4 (all independent) |
| 5 | 3 | 3 (all independent) |
| 6 | 2 | Sequential (submac -> mac) |
| 7 | 4 | ip6 first, then udp/icmp6/tcp parallel |
| 8 | 6 | key first, then others parallel |
| 9 | 9 | Mostly parallel |
| 10 | 6 | Mostly parallel |

## TDD Strategy

### Workflow Per Package

1. Write test file with all known test vectors (tests fail — no implementation).
2. Write the implementation to make tests pass.
3. Add fuzz tests for any parser/decoder functions.
4. Run `task lint` to verify code quality.
5. Add doc comments referencing the corresponding OpenThread source.

### Test Categories

1. **Unit tests** — Table-driven tests using extracted test vectors. Every package.
2. **Cross-reference tests** — Verify byte-for-byte output matches OpenThread (Phase 4+).
3. **Integration tests** — Multi-module tests (Phase 6+).
4. **Fuzz tests** — For all parsers: MAC frame, 6LoWPAN, DNS, CoAP, TLV (Phase 4+).

### Test Vector Sources

- **CRC:** 3 algorithms x 3 datasets from `test_crc.cpp`
- **Checksum:** RFC 1071 example, ICMP4 echo, Verhoeff from `test_checksum.cpp`
- **AES-CCM:** IEEE 802.15.4-2006 Annex C vectors from `test_aes.cpp`
- **SHA-256:** 4 vectors from `test_hmac_sha256.cpp`
- **HMAC-SHA-256:** RFC 4231 (5 test cases) from `test_hmac_sha256.cpp`
- **IPv6 addresses:** 15+ parse vectors, 6+ IPv4 vectors, 7 NAT64 vectors from `test_ip_address.cpp`
- **DNS names:** 4+ encoding vectors, subdomain matching from `test_dns.cpp`
- **MAC frames:** 45 header-length cases, 5+ PSDU parse vectors from `test_mac_frame.cpp`
- **6LoWPAN IPHC:** 30+ compression/decompression vectors from `test_lowpan.cpp`

Total: ~120+ test cases writable from day one with known expected outputs.

### Test Naming Convention

```
package_test.go      # Whitebox tests (same package)
package_ext_test.go  # Blackbox tests (_test package, public API validation)
```

Prefer blackbox tests to validate the public API surface.

## Tooling & CI

### Taskfile.yaml Tasks

| Task | Description |
|------|-------------|
| `test` | `go test ./...` |
| `test:race` | `go test -race ./...` |
| `test:cover` | Tests + coverage report |
| `lint` | `golangci-lint run ./...` |
| `fmt` | `gofmt -s -w .` |
| `fmt:check` | Verify formatting (CI) |
| `build` | `go build ./...` |
| `fuzz` | Run fuzz tests (30s per target) |
| `vet` | `go vet ./...` |
| `ci` | All CI checks (fmt:check + vet + lint + test) |

### GitHub Actions

- **ci.yml** — On push/PR: lint, test (with race detector), build. Parallel jobs.
- **fuzz.yml** — Scheduled nightly or manual: longer fuzz runs.

### golangci-lint

Standard linters: govet, errcheck, staticcheck, unused, gosimple, ineffassign, gocritic, gofmt.

## Attribution

- LICENSE: BSD 3-Clause, with attribution to the OpenThread project.
- README: Opening paragraph states this is a Go port of OpenThread, links to the original.
- Each package doc comment references the corresponding OpenThread module.

## OpenThread Architecture Reference

### Module Size (C++ lines of code)

| Module | Lines | Description |
|--------|------:|-------------|
| `thread/` | 55,398 | Thread protocol: MLE, mesh forwarding, 6LoWPAN, network data, routing |
| `net/` | 54,486 | IPv6 stack: IP6, UDP, TCP, ICMPv6, DNS, SRP, mDNS, DHCP6, NAT64 |
| `common/` | 20,943 | Foundation: timers, tasklets, messages, linked lists, encoding, TLVs |
| `meshcop/` | 19,476 | Mesh Commissioning: datasets, border agent, joiner, commissioner, DTLS |
| `mac/` | 15,709 | IEEE 802.15.4 MAC: framing, CSMA/CA, sub-MAC, filters, CSL |
| `border_router/` | 10,786 | Border routing: routing manager, RA tracking |
| `api/` | 9,578 | C API wrappers (not needed in Go port) |
| `utils/` | 9,898 | Utilities: channel manager, ping sender, history tracker |
| `config/` | 8,176 | Configuration defaults (maps to Go build tags / config structs) |
| `radio/` | 6,822 | Radio abstraction, TREL, BLE |
| `coap/` | 5,558 | CoAP protocol |
| `backbone_router/` | 3,746 | Backbone Router |
| `crypto/` | 3,320 | Crypto: AES-CCM, SHA-256, HMAC, HKDF |
| `instance/` | 2,031 | Instance singleton |
| `diags/` | 1,705 | Factory diagnostics |
| **TOTAL** | **227,757** | |

### Dependency Chain

```
Layer 0: Foundation (common/encoding, common/error, config/*)
Layer 1: Core Utilities (linked_list, pool, data, string, time, callback)
Layer 2: Infrastructure (tasklet, timer, message, notifier, settings, random, tlvs)
Layer 3: Crypto (AES-ECB, AES-CCM, SHA-256, HMAC-SHA-256, HKDF, ECDSA)
Layer 4: MAC Types + Radio (ExtAddress, ShortAddress, PanId, Frame, Radio interface)
Layer 5: Networking (IPv6 Address, Headers, Socket, Netif, UDP, ICMPv6, Checksum)
Layer 6: Thread Protocol (KeyManager, MLE, Lowpan, MeshForwarder, NetworkData)
Layer 7: MeshCoP + CoAP (Dataset, SecureTransport, Commissioner, Joiner, CoAP engine)
Layer 8: Services (DNS, SRP, mDNS, DHCP6)
Layer 9: Border Router (RoutingManager, BackboneRouter, NAT64)
Layer 10: Instance + Integration (Instance struct, API surface, CLI)
```
