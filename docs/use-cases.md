# gothread Use Cases & Applications

This document describes real-world use cases for `gothread` — a pure Go implementation
of the Thread 1.4.0 networking protocol. Each section covers the scenario, relevant
`gothread` packages, and how the library fits into the overall architecture.

---

## Table of Contents

1. [Smart Home / Building Automation](#1-smart-home--building-automation)
2. [Industrial IoT Sensor Networks](#2-industrial-iot-sensor-networks)
3. [Border Router](#3-border-router)
4. [Network Simulation & Testing](#4-network-simulation--testing)
5. [Protocol Research & Education](#5-protocol-research--education)
6. [OpenThread Interoperability Testing](#6-openthread-interoperability-testing)
7. [Embedded Go Devices](#7-embedded-go-devices)
8. [Custom Thread Network Tools](#8-custom-thread-network-tools)

---

## 1. Smart Home / Building Automation

### Description

Thread is the mesh networking layer powering modern smart home ecosystems. Devices
such as lights, motion sensors, temperature sensors, door locks, and thermostats
form a self-healing, low-power IPv6 mesh. `gothread` enables Go-based devices to
participate in these networks as full Thread nodes — end devices, routers, or
controllers — and interoperate with Matter and Apple HomeKit Thread accessories.

### Architecture

```
                        ┌─────────────────────────────────────┐
                        │         Home / Building LAN         │
                        │           (Wi-Fi / Ethernet)        │
                        └──────────────┬──────────────────────┘
                                       │
                              ┌────────┴────────┐
                              │  Border Router   │
                              │  (gothread +     │
                              │   border/ pkg)   │
                              └────────┬─────────┘
                                       │ IEEE 802.15.4
                    ┌──────────────────┼──────────────────┐
                    │                  │                   │
              ┌─────┴─────┐    ┌──────┴──────┐    ┌──────┴──────┐
              │  Light     │    │  Sensor     │    │  Lock       │
              │  (Router)  │◄──►│  (REED)     │◄──►│  (SED)      │
              │  gothread  │    │  gothread   │    │  gothread   │
              └─────┬──────┘    └─────────────┘    └─────────────┘
                    │
              ┌─────┴──────┐
              │  Thermostat │
              │  (Router)   │
              │  gothread   │
              └─────────────┘
```

### How gothread Fits

- **As a Thread node**: Use `instance/` to create a node, `thread/mle/` for mesh
  link establishment, and `thread/mesh/` for routing.
- **As a controller**: Use `meshcop/` for commissioning devices and `thread/mgmt/`
  for network management.
- **Matter / HomeKit**: Thread is the transport for Matter-over-Thread and HomeKit
  Thread accessories. A `gothread` border router (`border/router/`) bridges the
  mesh to IP, enabling Matter controllers to reach Thread devices.

### Key Packages

`instance/`, `thread/mle/`, `thread/mesh/`, `thread/key/`, `meshcop/`,
`border/router/`, `net/coap/`, `mac/`

---

## 2. Industrial IoT Sensor Networks

### Description

Factory floors, warehouses, and industrial facilities require dense, resilient
sensor networks for monitoring temperature, humidity, vibration, air quality,
and asset location. Thread's self-healing mesh topology is ideal: if a node
fails or a path is blocked, the network automatically re-routes traffic.
`gothread` brings this capability to Go-based industrial edge devices with
the full Thread routing stack.

### Architecture

```
    Factory Floor                                      Control Room
   ┌──────────────────────────────────────────┐     ┌──────────────┐
   │                                          │     │              │
   │  [Temp]──┐    ┌──[Vibration]             │     │  Monitoring  │
   │          │    │                           │     │  Dashboard   │
   │  [Humid]─┼────┤     Thread Mesh          │     │    (Go app)  │
   │          │    │      (802.15.4)           │     │              │
   │  [Air Q]─┘    └──[Asset Tag]             │     └──────┬───────┘
   │                       │                  │            │
   │               ┌───────┴───────┐          │            │
   │               │ Border Router │──────────┼────────────┘
   │               │ (gothread)    │  Ethernet│
   │               └───────────────┘          │
   └──────────────────────────────────────────┘
```

### Mesh Resilience & Self-Healing

- **Self-healing routing**: `thread/routing/` implements route discovery and repair.
  When a node goes offline, the mesh reconverges automatically.
- **Multi-hop**: Sensor data traverses multiple hops to the border router, extending
  range across large facilities.
- **No single point of failure**: The leader role (`thread/mle/`) migrates
  automatically if the current leader is lost.

### Key Packages

`thread/routing/`, `thread/mle/`, `thread/netdata/`, `thread/supervision/`,
`net/udp/`, `net/coap/`, `mac/datapoll/`, `mac/csl/`

---

## 3. Border Router

### Description

A Thread Border Router bridges the Thread mesh (IEEE 802.15.4) to external IP
networks (Wi-Fi, Ethernet). It enables Thread devices to communicate with cloud
services, mobile apps, and other IP hosts. `gothread` provides dedicated packages
for building a full-featured border router in pure Go, suitable for deployment on
Linux single-board computers such as a Raspberry Pi.

### Architecture

```
                    Internet / Cloud
                         │
                    ┌────┴────┐
                    │  Router  │
                    └────┬────┘
                         │  Ethernet / Wi-Fi
            ┌────────────┴────────────────────────┐
            │        Linux Host / Raspberry Pi     │
            │                                      │
            │  ┌──────────────────────────────┐    │
            │  │     gothread Border Router    │    │
            │  │                               │    │
            │  │  ┌──────────┐  ┌───────────┐  │    │
            │  │  │ border/  │  │ backbone/ │  │    │
            │  │  │ router/  │  │           │  │    │
            │  │  │          │  │ - leader  │  │    │
            │  │  │ - infra  │  │ - ndproxy │  │    │
            │  │  │   _if    │  │ - mcast   │  │    │
            │  │  │ - dhcp6  │  │   listen  │  │    │
            │  │  │   pd     │  │           │  │    │
            │  │  └──────────┘  └───────────┘  │    │
            │  │  ┌──────────┐  ┌───────────┐  │    │
            │  │  │ net/     │  │ thread/   │  │    │
            │  │  │ nat64/   │  │ bbr/      │  │    │
            │  │  │ nd6/     │  │           │  │    │
            │  │  │ srp/     │  │           │  │    │
            │  │  └──────────┘  └───────────┘  │    │
            │  └──────────────────────────────┘    │
            │           │  802.15.4 radio          │
            │     ┌─────┴─────┐                    │
            │     │  RCP/NCP  │ (USB/SPI/UART)     │
            │     └───────────┘                    │
            └──────────────────────────────────────┘
                         │
                   Thread Mesh
              ┌──────┬───┴───┬──────┐
              │      │       │      │
            [Dev1] [Dev2]  [Dev3] [Dev4]
```

### Go-Based Border Router on Linux / Raspberry Pi

1. **Single binary** — `go build` produces a statically-linked binary. Deploy by
   copying one file to the Pi.
2. **Cross-compilation** — `GOOS=linux GOARCH=arm64 go build` targets Raspberry Pi
   directly from any development machine.
3. **Concurrent I/O** — Goroutines handle Thread mesh traffic, IP forwarding,
   mDNS advertisement, and management API simultaneously.
4. **Infrastructure interface** — `border/infra_if.go` manages the upstream
   network interface, handling Router Advertisements and DHCPv6-PD.

### Key Packages

`border/router/`, `border/infra_if.go`, `border/dhcp6pd/`,
`border/rx_ra_tracker.go`, `backbone/`, `thread/bbr/`, `net/nat64/`, `net/nd6/`,
`net/srp/`, `net/mdns/`, `net/dnssd/`

---

## 4. Network Simulation & Testing

### Description

Testing Thread networks at scale typically requires expensive hardware (dozens of
radio boards) and complex physical setups. `gothread`'s simulation platform
(`platform/simulation/`) enables running entire Thread networks in software — no
hardware needed. Multiple simulated Thread nodes communicate via a shared simulated
radio medium, enabling repeatable, automated network testing.

### Architecture

```
    ┌─────────────────────────────────────────────────────────────┐
    │                    Go Test Process                          │
    │                                                             │
    │  ┌─────────┐  ┌─────────┐  ┌─────────┐     ┌─────────┐    │
    │  │ Node 1  │  │ Node 2  │  │ Node 3  │ ... │ Node N  │    │
    │  │ (Leader) │  │ (Router)│  │ (REED)  │     │ (SED)   │    │
    │  │         │  │         │  │         │     │         │    │
    │  │instance/│  │instance/│  │instance/│     │instance/│    │
    │  └────┬────┘  └────┬────┘  └────┬────┘     └────┬────┘    │
    │       │            │            │                │         │
    │  ┌────┴────────────┴────────────┴────────────────┴────┐    │
    │  │            platform/simulation/medium               │    │
    │  │                                                     │    │
    │  │  Simulated IEEE 802.15.4 Radio Channel              │    │
    │  │  - Frame delivery with configurable loss            │    │
    │  │  - RSSI / LQI simulation                            │    │
    │  │  - Channel filtering                                │    │
    │  └─────────────────────────────────────────────────────┘    │
    │                                                             │
    │  ┌─────────────────────────────────────────────────────┐    │
    │  │            Test Assertions & Validation              │    │
    │  │  - Network formation timing                         │    │
    │  │  - Routing table convergence                        │    │
    │  │  - Leader election under failure                    │    │
    │  │  - End-to-end data delivery                         │    │
    │  └─────────────────────────────────────────────────────┘    │
    └─────────────────────────────────────────────────────────────┘
```

### Simulation Components

- **`platform/simulation/sim.go`** — Core simulation platform implementing the
  `platform/` interface with simulated timers, entropy, and settings.
- **`platform/simulation/medium.go`** — Shared radio medium delivering 802.15.4
  frames between nodes with configurable topology and link quality.
- **`platform/simulation/radio.go`** — Simulated 802.15.4 radio transceiver.
- **`platform/simulation/udpradio.go`** — UDP-based radio for cross-process and
  cross-implementation testing.

### Key Packages

`platform/simulation/`, `platform/`, `instance/`, `radio/`

---

## 5. Protocol Research & Education

### Description

Understanding Thread's internals — MLE handshakes, 6LoWPAN compression, mesh
routing algorithms, network key rotation — typically means reading thousands of
lines of C++ in OpenThread. `gothread` offers the same protocol logic in idiomatic
Go, which is significantly more readable for researchers and students. Go's built-in
tooling (race detector, pprof, delve debugger) makes protocol analysis and
experimentation straightforward.

### Why Pure Go Matters for Research

- **Readable**: Go's simple syntax makes protocol state machines easy to follow.
- **Debuggable**: Use `dlv` to step through MLE handshakes or trace routing decisions.
- **Fuzzable**: Go's built-in fuzzing can target protocol parsers — `tlv/`,
  `mac/frame/`, `net/ip6/`, `thread/lowpan/`.
- **Profilable**: `go tool pprof` reveals CPU/memory hotspots in protocol processing.

### Research Areas

| Area | Packages |
|------|----------|
| MLE Protocol | `thread/mle/` |
| Mesh Routing | `thread/routing/` |
| 6LoWPAN | `thread/lowpan/` |
| MAC Security | `mac/`, `crypto/aesccm/` |
| Network Data | `thread/netdata/` |
| Commissioning | `meshcop/` |
| TLV Encoding | `tlv/` |
| CoAP/TMF | `net/coap/`, `thread/tmf/` |

---

## 6. OpenThread Interoperability Testing

### Description

Validating that a Thread implementation correctly interoperates with the reference
OpenThread (C++) implementation is critical for compliance. `gothread` includes
`UDPSimRadio` (`platform/simulation/udpradio.go`) — a UDP-based radio transport
that enables `gothread` nodes to exchange 802.15.4 frames with OpenThread's
simulation platform over UDP sockets. This allows cross-implementation testing
without any physical hardware.

### How It Works

```
  ┌───────────────────────┐          UDP          ┌───────────────────────┐
  │   gothread Process    │      (localhost)       │  OpenThread Process   │
  │                       │◄─────────────────────►│                       │
  │  ┌─────────────────┐  │   802.15.4 frames     │  ┌─────────────────┐  │
  │  │   instance/     │  │   over UDP sockets     │  │  ot-cli-ftd     │  │
  │  │   Thread Node   │  │                       │  │  (C++ Thread)   │  │
  │  └────────┬────────┘  │                       │  └────────┬────────┘  │
  │           │           │                       │           │           │
  │  ┌────────┴────────┐  │                       │  ┌────────┴────────┐  │
  │  │  UDPSimRadio    │  │                       │  │  UDP Radio Sim  │  │
  │  │  (udpradio.go)  │  │                       │  │  (simul_utils)  │  │
  │  └─────────────────┘  │                       │  └─────────────────┘  │
  └───────────────────────┘                       └───────────────────────┘
```

### Test Scenarios

- **Mixed mesh**: `gothread` leader with OpenThread routers (and vice versa).
- **Commissioning**: `gothread` commissioner onboarding an OpenThread joiner.
- **Routing**: End-to-end data across a mixed-implementation mesh.
- **Border Router**: `gothread` border router with OpenThread end devices.

The simulation platform includes interoperability tests
(`platform/simulation/interop_test.go`):

```bash
go test ./platform/simulation/ -run TestInterop -v
```

### Key Packages

`platform/simulation/udpradio.go`, `platform/simulation/interop_test.go`,
`meshcop/`, `thread/mle/`, `radio/`

---

## 7. Embedded Go Devices

### Description

As Go's embedded story matures — through TinyGo, WASM compilation targets, and
Go's improving support for constrained environments — `gothread` enables building
Thread-capable firmware entirely in Go. This brings Go's safety, concurrency, and
developer experience to embedded IoT devices.

### Current & Future Targets

| Target | Status | Notes |
|--------|--------|-------|
| Linux ARM (Raspberry Pi) | ✅ Ready | Full Thread stack via `GOARCH=arm64` |
| Linux RISC-V | ✅ Ready | Go supports `GOARCH=riscv64` |
| WASM (browser/WASI) | 🔄 Experimental | Simulation/testing in browser environments |
| TinyGo on MCUs | 🔮 Future | Requires TinyGo support for gothread's dependencies |

### Embedded Architecture

For Linux-capable embedded platforms (Raspberry Pi, BeagleBone, industrial SBCs),
the device runs `gothread` on Linux and communicates with an 802.15.4 radio chip
via SPI or UART through the `radio/` package abstraction.

### Considerations

- **Binary size**: Use `go build -ldflags="-s -w"` to minimize. Import only needed
  packages.
- **Memory**: For constrained devices, configure as a Sleepy End Device using
  `thread/supervision/` and `mac/datapoll/`.
- **Platform abstraction**: Implement the `platform/` interface for your hardware.
  `platform/simulation/` serves as a reference implementation.

### Key Packages

`platform/`, `radio/`, `instance/`, `mac/csl/`, `thread/supervision/`,
`mac/datapoll/`

---

## 8. Custom Thread Network Tools

### Description

`gothread` is not just for running Thread nodes — it's a library for building
Thread-aware tools. Because the protocol stack is implemented in Go, developers
can import specific packages to build CLI utilities, monitoring dashboards,
packet analyzers, and network management tools.

### Example Tools

#### Thread Network Scanner

```go
package main

import (
    "fmt"
    "github.com/hilli/gothread/thread/discover"
)

func main() {
    scanner := discover.NewScanner(radioDriver)
    for _, net := range scanner.Scan() {
        fmt.Printf("Network: %s  Channel: %d  PAN: 0x%04x\n",
            net.NetworkName, net.Channel, net.PanID)
    }
}
```

#### Packet Analyzer

Use `mac/frame/` to parse 802.15.4 frames, `thread/mle/` to decode MLE messages,
and `tlv/` for TLV structures. Combine with `net/coap/` for application-layer
decoding.

#### Network Diagnostics Dashboard

Use `diags/`, `thread/netdata/`, and `thread/linkmetrics/` to query neighbor
tables, routing tables, and link quality — then serve via HTTP.

### Key Packages

`thread/discover/`, `mac/frame/`, `thread/mle/`, `tlv/`, `net/coap/`, `diags/`,
`thread/netdata/`, `thread/linkmetrics/`, `meshcop/`, `encoding/`,
`cmd/gothread/`

---

## Getting Started

To explore any of these use cases:

```bash
# Clone the repository
git clone https://github.com/hilli/gothread.git
cd gothread

# Run the simulation tests to see multi-node Thread networking in action
go test ./platform/simulation/ -v

# Build the CLI tool
go build ./cmd/gothread/

# Run all tests
task test
```

For implementation plans and roadmap, see [docs/plans/](plans/).
