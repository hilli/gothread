# gothread

A pure Go implementation of the [Thread](https://www.threadgroup.org/What-is-Thread/Overview) 1.4.0 networking protocol.

This project is a port of [OpenThread](https://github.com/openthread/openthread), Google's open-source C++ implementation of the Thread networking protocol. `gothread` aims to provide a fully independent, idiomatic Go implementation of the complete Thread protocol stack. 

## Status

Early development. See [docs/plans/](docs/plans/) for the implementation plan.

## Thread Protocol

Thread is a low-power, IPv6-based mesh networking protocol designed for IoT and connected home devices. It operates over IEEE 802.15.4 radio and provides:

- IPv6 networking with 6LoWPAN header compression
- IEEE 802.15.4 MAC layer with security
- Mesh Link Establishment (MLE)
- Mesh routing
- Border Router support
- Mesh Commissioning Protocol (MeshCoP)

## Building

Requires Go 1.25+ and [Task](https://taskfile.dev/).

```sh
task build     # Build all packages
task test      # Run all tests
task lint      # Run linter
task ci        # Run all CI checks
```

## License

BSD 3-Clause License. See [LICENSE](LICENSE).

This project is a port of OpenThread, which is Copyright (c) 2016, The OpenThread Authors, also under the BSD 3-Clause License.

`gothread` is in NO WAY affiliated with Nest, Google, or The Thread Group.

This library is verified against github.com/openthread/openthread@3f11074f1e188bd84d7d530da271ce5bc66bc3ec
