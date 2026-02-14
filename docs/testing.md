# Testing Guide

This guide covers how to build and test gothread from a fresh checkout,
including the optional OpenThread interop tests.

## Prerequisites

| Tool | Required | Purpose |
|------|----------|---------|
| **Go 1.25+** | Yes | Build & test |
| **Git** | Yes | Clone repos |
| **CMake 3.16+** | Interop only | Build OpenThread |
| **Ninja** | Interop only | CMake build backend |
| **C/C++ compiler** | Interop only | Build OpenThread |
| **Task** (taskfile.dev) | Optional | Task runner (`task test`) |

### Install prerequisites (macOS)

```sh
brew install go cmake ninja
# Optional:
brew install go-task golangci-lint
```

### Install prerequisites (Ubuntu/Debian)

```sh
sudo apt-get update
sudo apt-get install -y golang cmake ninja-build gcc g++ git
# Optional:
# Install Task from https://taskfile.dev/installation/
# Install golangci-lint from https://golangci-lint.run/welcome/install/
```

## Quick Start

```sh
git clone https://github.com/hilli/gothread.git
cd gothread
go test ./...
```

That's it — all 98 packages will build and pass. The interop test is
automatically skipped when the OpenThread binary is not present.

## Running Tests

### All tests

```sh
go test ./...
# or with Task:
task test
```

### Verbose output

```sh
go test -v ./...
# or:
task test:verbose
```

### With race detector

```sh
go test -race ./...
# or:
task test:race
```

### With coverage

```sh
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
# or:
task test:cover
```

### Specific package

```sh
go test ./platform/simulation/...
go test ./thread/mesh/...
go test ./instance/...
```

### Short mode (skip slow tests)

```sh
go test -short ./...
```

This skips the OpenThread interop test even if the binary is available.

## OpenThread Interop Tests

The interop test (`TestInteropReceiveOTFrame`) starts a real OpenThread
simulation node and verifies that gothread can receive and parse its
802.15.4 frames over UDP multicast. It requires building the OpenThread
CLI binary first.

### Setup

1. **Clone OpenThread** into the repo root:

   ```sh
   cd gothread
   git clone https://github.com/openthread/openthread.git
   ```

2. **Build the simulation CLI:**

   ```sh
   cd openthread
   OT_CMAKE_NINJA_TARGET="ot-cli-ftd" script/cmake-build simulation
   ```

   On **macOS ARM64**, if you hit mbedTLS linker errors, disable TCP:

   ```sh
   OT_CMAKE_NINJA_TARGET="ot-cli-ftd" \
     OT_CMAKE_BUILD_SHARED_LIBS=OFF \
     script/cmake-build simulation -DOT_TCP=OFF
   ```

3. **Verify the binary exists:**

   ```sh
   ls -la openthread/build/simulation/examples/apps/cli/ot-cli-ftd
   ```

### Run the interop test

```sh
go test -v ./platform/simulation/... -run TestInteropReceiveOTFrame -timeout 120s
```

> **Note:** This test takes ~40 seconds because the OpenThread simulation node
> needs ~36 seconds to self-elect as Thread leader before it begins
> transmitting beacons.

### What it does

1. Starts an `ot-cli-ftd` subprocess (node ID 1, port base 9000)
2. Configures a Thread dataset and starts the Thread stack
3. Creates a gothread `UDPSimRadio` (node ID 2) listening on the same
   multicast group (`224.0.0.116:9000`)
4. Waits for the OT node to become leader (~36s)
5. Triggers a Discovery Request via `discover` CLI command
6. Captures received 802.15.4 frames and parses them
7. Verifies frame structure (type, PAN ID, addressing)

## All CI Checks

Run the full CI suite (formatting, vet, lint, race-detected tests):

```sh
task ci
```

Or manually:

```sh
gofmt -s -l .          # check formatting
go vet ./...           # static analysis
golangci-lint run ./...  # linting
go test -race ./...    # tests with race detector
```

## Automated Setup Script

A convenience script is provided to set up everything from scratch,
including the optional OpenThread interop binary:

```sh
./scripts/setup-and-test.sh
```

See [scripts/setup-and-test.sh](../scripts/setup-and-test.sh) for details.
