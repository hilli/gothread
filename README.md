# gothread

A pure Go implementation of the [Thread](https://www.threadgroup.org/What-is-Thread/Overview) 1.4.0 networking protocol.

This project is a port of [OpenThread](https://github.com/openthread/openthread), Google's open-source C++ implementation of the Thread networking protocol. `gothread` provides a fully independent, idiomatic Go implementation of the complete Thread protocol stack — no CGo, no external dependencies.

## Highlights

- **98 packages**, all building and passing tests
- **Thread 1.4.0** — MLE, mesh routing, 6LoWPAN, MeshCoP, Border Router
- **IEEE 802.15.4** MAC layer with AES-CCM security
- **Simulation platform** for multi-node testing without hardware
- **OpenThread interop** — receives and parses frames from live OT nodes
- **Interactive CLI** for exploring Thread networks

## Quick Start

```sh
git clone https://github.com/hilli/gothread.git
cd gothread
go test ./...          # Run all tests (98 packages)
go run ./cmd/gothread  # Interactive CLI simulator
```

See the [Getting Started Guide](docs/getting-started.md) for detailed setup.

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Installation, CLI usage, first steps |
| [Architecture](docs/architecture.md) | System design, layer stack, data flow |
| [API Overview](docs/api-overview.md) | Key interfaces, types, and package guide |
| [Examples](docs/examples.md) | Runnable code examples for common tasks |
| [Use Cases](docs/use-cases.md) | Real-world applications and scenarios |
| [Spec Compliance](docs/spec-compliance.md) | Thread 1.4.0 / RFC feature matrix |
| [Testing Guide](docs/testing.md) | Running tests, OpenThread interop setup |

## Building

Requires Go 1.25+. [Task](https://taskfile.dev/) is optional.

```sh
go build ./...         # Build all packages
go test ./...          # Run all tests
go test -race ./...    # With race detector

# Or with Task:
task build
task test
task ci                # Full CI: fmt + vet + lint + race tests
```

## OpenThread Interop

gothread can exchange 802.15.4 frames with OpenThread simulation nodes:

```sh
./scripts/setup-and-test.sh --interop   # Clone OT, build, run interop test
```

See [Testing Guide — OpenThread Interop](docs/testing.md#openthread-interop-tests) for details.

## License

BSD 3-Clause License. See [LICENSE](LICENSE).

This project is a port of OpenThread, which is Copyright (c) 2016, The OpenThread Authors, also under the BSD 3-Clause License.

`gothread` is in NO WAY affiliated with Nest, Google, or The Thread Group.

Verified against [`openthread@3f11074`](https://github.com/openthread/openthread/tree/3f11074f1e188bd84d7d530da271ce5bc66bc3ec).
