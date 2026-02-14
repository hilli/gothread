# Getting Started with gothread

This guide walks you through installing, building, and running your first
Thread simulation node with **gothread** — a pure Go implementation of the
[Thread 1.4.0](https://www.threadgroup.org/What-is-Thread/Overview)
networking protocol.

## What is gothread?

gothread is a from-scratch Go port of
[OpenThread](https://github.com/openthread/openthread), the reference C++
Thread implementation. It provides the complete Thread protocol stack in
idiomatic Go:

- **Pure Go, no CGo** — builds with `go build`, cross-compiles trivially.
- **IEEE 802.15.4 MAC** with frame security and filtering.
- **Mesh Link Establishment (MLE)** — role election, leader/router/child
  lifecycle.
- **6LoWPAN / IPv6** — header compression, mesh forwarding, SLAAC.
- **MeshCoP** — commissioning, operational datasets.
- **Border Router** support, DNS-SD, SRP, NAT64, and more.

A simulation platform lets you run Thread nodes entirely in memory — no
radio hardware required.

## Prerequisites

| Tool | Required | Purpose |
|------|----------|---------|
| **Go 1.25+** | Yes | Build & test |
| **Git** | Yes | Clone the repository |
| **[Task](https://taskfile.dev)** | Optional | Convenient task runner |
| **[golangci-lint](https://golangci-lint.run)** | Optional | Linting |

### macOS

```sh
brew install go
# Optional:
brew install go-task golangci-lint
```

### Ubuntu / Debian

```sh
sudo apt-get update && sudo apt-get install -y golang git
# Optional — see https://taskfile.dev/installation/
```

## Installation

### As a library

```sh
go get github.com/hilli/gothread@latest
```

### From source

```sh
git clone https://github.com/hilli/gothread.git
cd gothread
go build ./...
```

Or with Task:

```sh
task build
```

## Quick Start: CLI Simulator

gothread ships with a ready-to-run CLI node at `cmd/gothread`. It creates
a simulation platform, starts a Thread node, and drops you into an
interactive REPL.

### Run the node

```sh
go run ./cmd/gothread \
  --channel 15 \
  --panid 0x1234 \
  --network-name "MyThread"
```

All flags are optional (defaults: channel 11, PAN ID 0xABCD, name
"GoThread").

### REPL commands

Once the node starts you'll see a `>` prompt. Available commands:

| Command | Description |
|---------|-------------|
| `state` | Role, RLOC16, channel, PAN ID, network name |
| `ipaddr` | IPv6 unicast addresses |
| `channel` | Current radio channel |
| `panid` | Current PAN ID |
| `rloc16` | RLOC16 short address |
| `extaddr` | Extended MAC address |
| `leaderdata` | Leader partition ID and RLOC |
| `networkname` | Network name |
| `extpanid` | Extended PAN ID |
| `help` | List all commands |
| `exit` / `quit` | Shutdown the node |

Example session:

```
GoThread v0.1 — Thread Simulation Node
  Channel:      15
  PAN ID:       0x1234
  Network Name: MyThread
Node started. Type 'help' for commands, 'exit' to quit.
> state
Role:         Leader
RLOC16:       0xC800
Channel:      15
PAN ID:       0x1234
Network Name: MyThread
> ipaddr
fe80:0:0:0:a0e5:3b2f:7c01:d4f8/64
> exit
Shutting down...
```

## Quick Start: Programmatic Usage

You can embed gothread directly in your own Go programs. The key types
are:

- `platform/simulation.Platform` — in-memory simulation (alarm, entropy,
  settings, logger, radio).
- `instance.Config` — platform bindings passed to the instance constructor.
- `instance.Instance` — the Thread node itself.

### Minimal example

```go
package main

import (
	"fmt"
	"time"

	"github.com/hilli/gothread/instance"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/platform/simulation"
)

func main() {
	// 1. Create a simulation platform (alarm, entropy, settings, logger, radio).
	plat := simulation.NewPlatform()

	// 2. Create a Thread instance with the simulated platform.
	inst := instance.New(instance.Config{
		Alarm:    plat.Alarm,
		Entropy:  plat.Entropy,
		Settings: plat.Settings,
		Logger:   plat.Logger,
		Radio:    plat.Radio,
	})

	// 3. Configure MAC parameters.
	inst.Mac().SetPanChannel(15)
	inst.Mac().SetPanID(types.PanID(0x1234))
	inst.Mac().SetNetworkName("MyThread")

	// 4. Start the event loop.
	if err := inst.Start(); err != nil {
		panic(err)
	}
	defer inst.Stop()

	// 5. Bring up the network interface (enables MAC + mesh forwarder).
	if err := inst.IfConfigUp(); err != nil {
		panic(err)
	}

	// 6. Give the node a moment to attach and elect itself leader.
	time.Sleep(2 * time.Second)

	// 7. Read node state.
	mle := inst.MleService().Mle()
	fmt.Printf("Role:         %s\n", mle.Role())
	fmt.Printf("RLOC16:       0x%04X\n", inst.RLOC16())
	fmt.Printf("Channel:      %d\n", inst.Mac().GetPanChannel())
	fmt.Printf("PAN ID:       0x%04X\n", inst.Mac().GetPanID())
	fmt.Printf("Network Name: %s\n", inst.Mac().GetNetworkName())

	// 8. List IPv6 addresses.
	for _, a := range inst.Netif().GetUnicastAddresses() {
		fmt.Printf("  %v/%d\n", a.Address, a.PrefixLength)
	}
}
```

## Running Tests

All packages include unit tests. From the repo root:

```sh
go test ./...
# With race detector:
go test -race ./...
# With coverage:
go test -coverprofile=coverage.out ./...
```

Or use Task shortcuts:

```sh
task test          # go test ./...
task test:race     # with -race
task test:cover    # with coverage report
task test:verbose  # with -v
task ci            # fmt + vet + lint + race tests
```

A convenience script builds everything from scratch, including the
optional OpenThread interop binary:

```sh
./scripts/setup-and-test.sh
```

For the full testing guide — including per-package tests, fuzz testing,
and CI checks — see [docs/testing.md](testing.md).

## Two-Node Simulation

The `simulation.Medium` type simulates a shared RF medium. When one radio
transmits, the medium delivers a copy to every other radio tuned to the
same channel. This lets you run a multi-node Thread network entirely in
memory.

```go
package main

import (
	"fmt"
	"time"

	"github.com/hilli/gothread/instance"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/platform/simulation"
)

func main() {
	// Create a shared RF medium.
	medium := simulation.NewMedium()

	// Helper to create and start a node on the shared medium.
	makeNode := func(name string, channel uint8, panID uint16) *instance.Instance {
		plat := simulation.NewPlatform()
		medium.Register(plat.Radio) // connect radio to the shared medium

		inst := instance.New(instance.Config{
			Alarm:    plat.Alarm,
			Entropy:  plat.Entropy,
			Settings: plat.Settings,
			Logger:   plat.Logger,
			Radio:    plat.Radio,
		})

		inst.Mac().SetPanChannel(channel)
		inst.Mac().SetPanID(types.PanID(panID))
		inst.Mac().SetNetworkName(name)

		if err := inst.Start(); err != nil {
			panic(err)
		}
		if err := inst.IfConfigUp(); err != nil {
			panic(err)
		}
		return inst
	}

	node1 := makeNode("TwoNodeNet", 15, 0x1234)
	node2 := makeNode("TwoNodeNet", 15, 0x1234)
	defer node1.Stop()
	defer node2.Stop()

	// Wait for the nodes to discover each other and form a network.
	time.Sleep(5 * time.Second)

	fmt.Printf("Node 1 role: %s\n", node1.MleService().Mle().Role())
	fmt.Printf("Node 2 role: %s\n", node2.MleService().Mle().Role())
}
```

The `Medium` broadcasts frames to all registered radios on the same
channel that are in the receive state, skipping the sender. This is
the same mechanism the test suite uses for multi-node integration
tests.

## OpenThread Interop

gothread includes an interop test that starts a real OpenThread
simulation node (`ot-cli-ftd`) and verifies that gothread can receive
and correctly parse its IEEE 802.15.4 frames over UDP multicast.

To run it:

1. Clone and build OpenThread (see [docs/testing.md](testing.md#openthread-interop-tests)).
2. Run the interop test:

   ```sh
   go test -v ./platform/simulation/... -run TestInteropReceiveOTFrame -timeout 120s
   ```

The test validates that gothread's frame parsing is wire-compatible with
the reference C++ implementation — an important correctness guarantee for
real-world deployments.

## Next Steps

- **[Testing Guide](testing.md)** — full details on running tests,
  coverage, fuzz testing, and CI.
- **[Port Design](plans/2026-02-08-gothread-port-design.md)** —
  architecture and design decisions behind the Go port.
- **[Instance Wiring](plans/2026-02-11-instance-wiring-design.md)** —
  how all Thread stack modules are created and connected.
- **[README](../README.md)** — project overview and build instructions.
- **[GoDoc](https://pkg.go.dev/github.com/hilli/gothread)** — API
  reference for all packages.
