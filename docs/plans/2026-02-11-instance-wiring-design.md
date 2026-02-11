# Phase 28: Instance Wiring Design

**Date:** 2026-02-11
**Status:** Approved

## Goal

Wire all 97+ protocol packages into a working Thread stack via the central
`instance.Instance` struct. After this phase, creating an Instance with
platform dependencies produces a fully connected Thread stack ready to
attach to a network.

## Approach

**3-tier incremental wiring.** Each tier adds modules, adapter methods on
Instance, and integration tests.

### Tier 1 — Radio/MAC/Key Core

Modules: `message.Pool`, `settings.Settings`, `notifier.Notifier`,
`key.Manager`, `submac.SubMac`, `mac.Mac`

Wiring chain:
```
radio.Radio → submac.New(Config{Radio, Callbacks: mac, Timer: inst})
           → mac.New(Config{SubMac, Callbacks: inst, Timer: inst})
```

Instance implements `mac.Callbacks` (3 methods): `HandleFrameRequest`,
`HandleSentFrame`, `HandleReceivedFrame`. In Tier 1, HandleReceivedFrame
is a no-op stub; Tier 3 fills it in to forward frames to the mesh
forwarder.

Mac itself already implements `submac.Callbacks`, so no adapter is needed
for the submac→mac link.

### Tier 2 — Routing/MLE/Network

Modules: `routing.RouterTable`, `routing.ChildTable`,
`routing.NeighborTable`, `mle.Service`, `ip6.Netif`, `udp.UDP`

Wiring:
```
RouterTable + ChildTable → NeighborTable
Instance implements mle.Transport, mle.KeyProvider (delegates to key.Manager),
    mle.RouterLookup (delegates to RouterTable),
    mle.RouteDataProvider, mle.AdvertisementRouterOps,
    mle.ConnectivityProvider, mle.NetworkInfoProvider
→ mle.NewService(ServiceConfig{...})
```

### Tier 3 — Application Layer

Modules: `coap.Engine`, `tmf.Agent`, `netdata.Leader`,
`mesh.Forwarder`, `tmf.LeaderService`, `tmf.ServerDataService`

Wiring:
```
Instance provides coap.Sender func → coap.NewEngine(sender)
→ tmf.NewAgent(engine)
RouterTable implements netdata.RouterChecker → netdata.NewLeader(rt)
→ tmf.NewLeaderService(agent, routerTable, threshold)
→ tmf.NewServerDataService(agent, leader)
mesh.NewForwarder() ← Instance.HandleReceivedFrame now routes here
```

## Instance Struct Additions

```go
type Instance struct {
    // --- existing fields (platform, event loop, timers, notifier) ---

    // Tier 1
    messagePool *message.Pool
    settings    *csettings.Settings
    cnotifier   *cnotifier.Notifier
    keyManager  *key.Manager
    subMac      *submac.SubMac
    mac         *mac.Mac

    // Tier 2
    routerTable   *routing.RouterTable
    childTable    *routing.ChildTable
    neighborTable *routing.NeighborTable
    mleService    *mle.Service
    netif         *ip6.Netif
    udp           *udp.UDP

    // Tier 3
    coapEngine  *coap.Engine
    tmfAgent    *tmf.Agent
    netdataLdr  *netdata.Leader
    forwarder   *mesh.Forwarder
}
```

## Adapter Methods on Instance

Instance implements these interfaces via methods that delegate to owned
modules:

| Interface | Methods | Delegates to |
|---|---|---|
| `mac.Callbacks` | HandleFrameRequest, HandleSentFrame, HandleReceivedFrame | mesh.Forwarder, mle.Service |
| `mle.Transport` | SendMLE, GetExtAddress, GetLinkLocalAddress, GetMeshLocalAddress, GetLinkLocalAllRoutersMulticast | udp.UDP, netif |
| `mle.KeyProvider` | GetCurrentKeySequence, GetCurrentMleKey, etc. | key.Manager |
| `mle.RouterLookup` | FindRouterByRloc16, FindRouterByExtAddress | routing.RouterTable |
| `mle.RouteDataProvider` | GetRouteData | routing.RouterTable |
| `mle.AdvertisementRouterOps` | ProcessRouteTlv, UpdateRoutes | routing.RouterTable |
| `mle.ConnectivityProvider` | GetConnectivity | routing tables |
| `mle.NetworkInfoProvider` | GetNetworkName, GetExtPanID, GetSteeringData | settings/config |
| `coap.Sender` | (func type) | udp.UDP |
| `netdata.RouterChecker` | IsRouterIDAllocated | routing.RouterTable |

## Constructor Flow

```go
func New(config Config) *Instance {
    inst := &Instance{...platform fields...}

    // Tier 1
    inst.messagePool = message.NewPool(256)
    inst.cnotifier = cnotifier.New()
    inst.keyManager = key.NewManager()
    if config.Settings != nil {
        inst.settings = csettings.New(platformSettingsAdapter{config.Settings})
    }
    inst.subMac = submac.New(submac.Config{
        Radio:         config.Radio,
        ScheduleTimer: inst.scheduleTimerInternal,
        StopTimer:     inst.stopTimerInternal,
    })
    inst.mac = mac.New(mac.Config{
        SubMac:        inst.subMac,
        Callbacks:     inst,  // Instance implements mac.Callbacks
        ScheduleTimer: inst.scheduleTimerInternal,
        StopTimer:     inst.stopTimerInternal,
        PostOperation: inst.postOperationInternal,
    })
    // Mac implements submac.Callbacks — wire it
    inst.subMac.SetCallbacks(inst.mac)  // or set during submac.New

    // Tier 2
    inst.routerTable = routing.NewRouterTable()
    inst.childTable = routing.NewChildTable()
    inst.neighborTable = routing.NewNeighborTable(inst.routerTable, inst.childTable)
    inst.netif = ip6.NewNetif()
    inst.udp = udp.New()
    inst.mleService = mle.NewService(mle.ServiceConfig{
        Transport:      inst,
        KeyProvider:    inst,
        RouterLookup:   inst,
        RouteData:      inst,
        RouterOps:      inst,
        Connectivity:   inst,
        NetworkInfo:    inst,
        NeighborLookup: inst.neighborTable.FindNeighborByExtAddress,
    })

    // Tier 3
    inst.coapEngine = coap.NewEngine(inst.sendCoAP)
    inst.tmfAgent = tmf.NewAgent(inst.coapEngine)
    inst.netdataLdr = netdata.NewLeader(inst.routerTable)
    inst.forwarder = mesh.NewForwarder()

    return inst
}
```

## Testing Strategy

Each tier gets an integration test file (`instance/instance_tier1_test.go`,
etc.) that:

1. Creates an Instance with mock platform dependencies
2. Exercises the wiring by triggering events at the boundary (e.g., mock
   radio delivers a frame → verify it propagates through submac → mac →
   Instance.HandleReceivedFrame)
3. Verifies module state changes through public accessors

## File Layout

All wiring code lives in `instance/`:
- `instance.go` — Instance struct, New(), event loop (existing + expanded)
- `adapters.go` — Interface adapter methods on Instance
- `instance_test.go` — Existing tests (expanded)
- `instance_tier1_test.go` — Tier 1 integration tests
- `instance_tier2_test.go` — Tier 2 integration tests
- `instance_tier3_test.go` — Tier 3 integration tests
