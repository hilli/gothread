# GoThread Code Examples

Practical examples for the `github.com/hilli/gothread` Thread 1.4.0 networking stack.

---

## 1. Minimal Thread Node

Create a Thread node using the simulation platform, configure an operational
dataset, and start the Thread protocol.

```go
package main

import (
	"fmt"
	"time"

	"github.com/hilli/gothread/instance"
	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/mle"
)

func main() {
	// Create a simulation platform with all components.
	plat := simulation.NewPlatform()

	// Build the Thread instance from platform components.
	inst := instance.New(instance.Config{
		Alarm:    plat.Alarm,
		Entropy:  plat.Entropy,
		Settings: plat.Settings,
		Logger:   plat.Logger,
		Radio:    plat.Radio,
	})

	// Configure the Active Operational Dataset.
	dsInfo := &meshcop.Info{
		Channel:     15,
		PanID:       0xABCD,
		NetworkKey:  [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		NetworkName: "GoThreadNet",
		Components: meshcop.Components{
			Channel:    true,
			PanID:      true,
			NetworkKey: true,
			NetworkName: true,
		},
	}
	ds := meshcop.InfoToDataset(dsInfo)
	fmt.Printf("Dataset length: %d bytes\n", ds.Length())

	// Start the event loop.
	if err := inst.Start(); err != nil {
		panic(err)
	}

	// Bring up the network interface and start Thread.
	inst.PostTask(func() {
		if err := inst.IfConfigUp(); err != nil {
			fmt.Printf("IfConfigUp error: %v\n", err)
			return
		}
		if err := inst.ThreadStart(); err != nil {
			fmt.Printf("ThreadStart error: %v\n", err)
			return
		}
		fmt.Println("Thread started, role:", inst.MleService().Mle().Role())
	})

	// Let the node run briefly, then shut down.
	time.Sleep(2 * time.Second)

	inst.PostTask(func() {
		role := inst.MleService().Mle().Role()
		fmt.Println("Current role:", role)
	})
	time.Sleep(100 * time.Millisecond)

	inst.Stop()
	fmt.Println("Node stopped.")
}
```

**Expected output:**
```
Dataset length: 40 bytes
Thread started, role: Detached
Current role: Detached
Node stopped.
```

---

## 2. Two-Node Mesh Network

Use `Medium` to connect two `SimRadio` instances, create two Thread nodes,
and show frames being delivered between them.

```go
package main

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/radio"
)

func main() {
	// Create a shared RF medium.
	medium := simulation.NewMedium()

	// Create two simulated radios and register them on the medium.
	radio1 := simulation.NewSimRadio()
	radio2 := simulation.NewSimRadio()
	medium.Register(radio1)
	medium.Register(radio2)

	// Track received frames on each radio.
	var r1Count, r2Count int64

	radio1.SetReceiveCallback(func(f *radio.Frame) {
		atomic.AddInt64(&r1Count, 1)
		fmt.Printf("Radio1 received %d bytes on channel %d\n", len(f.PSDU), f.Channel)
	})
	radio2.SetReceiveCallback(func(f *radio.Frame) {
		atomic.AddInt64(&r2Count, 1)
		fmt.Printf("Radio2 received %d bytes on channel %d\n", len(f.PSDU), f.Channel)
	})

	// Enable both radios and set them to receive on channel 15.
	radio1.Enable()
	radio2.Enable()
	radio1.Receive(15)
	radio2.Receive(15)

	fmt.Println("Radio1 state:", radio1.GetState())
	fmt.Println("Radio2 state:", radio2.GetState())

	// Transmit a frame from radio1 — radio2 should receive it.
	frame := &radio.Frame{
		PSDU:    []byte{0x41, 0x88, 0x01, 0xCD, 0xAB, 0xFF, 0xFF, 0x01, 0x00,
			0x48, 0x65, 0x6C, 0x6C, 0x6F}, // "Hello" payload
		Channel: 15,
	}
	radio1.Transmit(frame)
	time.Sleep(50 * time.Millisecond)

	// Transmit from radio2 back to radio1.
	reply := &radio.Frame{
		PSDU:    []byte{0x41, 0x88, 0x02, 0xCD, 0xAB, 0xFF, 0xFF, 0x00, 0x01,
			0x57, 0x6F, 0x72, 0x6C, 0x64}, // "World" payload
		Channel: 15,
	}
	radio2.Transmit(reply)
	time.Sleep(50 * time.Millisecond)

	fmt.Printf("Radio1 received %d frame(s)\n", atomic.LoadInt64(&r1Count))
	fmt.Printf("Radio2 received %d frame(s)\n", atomic.LoadInt64(&r2Count))

	// Cleanup.
	medium.Unregister(radio1)
	medium.Unregister(radio2)
	fmt.Println("Medium cleared.")
}
```

**Expected output:**
```
Radio1 state: Receive
Radio2 state: Receive
Radio2 received 14 bytes on channel 15
Radio1 received 14 bytes on channel 15
Radio1 received 1 frame(s)
Radio2 received 1 frame(s)
Medium cleared.
```

---

## 3. Custom Radio Implementation

Implement the `radio.Radio` interface to integrate custom hardware or a
test harness.

```go
package main

import (
	"fmt"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/radio"
)

// LoggingRadio wraps any radio.Radio and logs every method call.
type LoggingRadio struct {
	state   radio.State
	channel uint8
	eui64   [8]byte
	txBuf   radio.Frame
	txPower int8
	panID   uint16
}

// Compile-time check that LoggingRadio satisfies radio.Radio.
var _ radio.Radio = (*LoggingRadio)(nil)

func (r *LoggingRadio) Enable() error {
	r.state = radio.StateSleep
	fmt.Println("Radio: Enable")
	return nil
}

func (r *LoggingRadio) Disable() error {
	r.state = radio.StateDisabled
	fmt.Println("Radio: Disable")
	return nil
}

func (r *LoggingRadio) IsEnabled() bool { return r.state != radio.StateDisabled }
func (r *LoggingRadio) GetState() radio.State { return r.state }

func (r *LoggingRadio) Sleep() error {
	r.state = radio.StateSleep
	fmt.Println("Radio: Sleep")
	return nil
}

func (r *LoggingRadio) Receive(channel uint8) error {
	r.state = radio.StateReceive
	r.channel = channel
	fmt.Printf("Radio: Receive on channel %d\n", channel)
	return nil
}

func (r *LoggingRadio) Transmit(frame *radio.Frame) error {
	r.state = radio.StateTransmit
	fmt.Printf("Radio: Transmit %d bytes on channel %d\n", len(frame.PSDU), frame.Channel)
	return nil
}

func (r *LoggingRadio) GetTransmitBuffer() *radio.Frame   { return &r.txBuf }
func (r *LoggingRadio) GetCaps() radio.Caps                { return radio.CapNone }
func (r *LoggingRadio) GetIEEEEui64() [8]byte              { return r.eui64 }
func (r *LoggingRadio) SetPanID(panID uint16)               { r.panID = panID }
func (r *LoggingRadio) SetExtendedAddress(addr types.ExtAddress) {}
func (r *LoggingRadio) SetShortAddress(addr types.ShortAddress)  {}
func (r *LoggingRadio) GetTransmitPower() (int8, error)     { return r.txPower, nil }
func (r *LoggingRadio) SetTransmitPower(power int8) error   { r.txPower = power; return nil }
func (r *LoggingRadio) GetPromiscuous() bool                { return false }
func (r *LoggingRadio) SetPromiscuous(enable bool)          {}
func (r *LoggingRadio) GetRSSI() int8                       { return -60 }
func (r *LoggingRadio) GetSupportedChannelMask() uint32     { return 0x07FFF800 }
func (r *LoggingRadio) GetPreferredChannelMask() uint32     { return 0x07FFF800 }
func (r *LoggingRadio) GetReceiveSensitivity() int8         { return -100 }

// Source address match (frame-pending bit in ACKs).
func (r *LoggingRadio) EnableSrcMatch(enable bool)                           {}
func (r *LoggingRadio) AddSrcMatchShortEntry(addr types.ShortAddress) error  { return nil }
func (r *LoggingRadio) AddSrcMatchExtEntry(addr types.ExtAddress) error      { return nil }
func (r *LoggingRadio) ClearSrcMatchShortEntry(addr types.ShortAddress) error { return nil }
func (r *LoggingRadio) ClearSrcMatchExtEntry(addr types.ExtAddress) error    { return nil }
func (r *LoggingRadio) ClearSrcMatchShortEntries()                           {}
func (r *LoggingRadio) ClearSrcMatchExtEntries()                             {}

// Security.
func (r *LoggingRadio) SetMacKey(keyIDMode, keyID uint8, prev, curr, next types.KeyMaterial) {}
func (r *LoggingRadio) SetMacFrameCounter(counter uint32)            {}
func (r *LoggingRadio) SetMacFrameCounterIfLarger(counter uint32)    {}

// Energy scan.
func (r *LoggingRadio) EnergyScan(channel uint8, duration uint16) error { return nil }

func main() {
	r := &LoggingRadio{
		eui64: [8]byte{0x18, 0xB4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x42},
	}

	r.Enable()
	r.Receive(11)
	fmt.Println("State:", r.GetState())
	fmt.Println("Caps:", r.GetCaps())
	fmt.Printf("EUI-64: %X\n", r.GetIEEEEui64())

	r.Transmit(&radio.Frame{
		PSDU:    []byte{0x01, 0x02, 0x03},
		Channel: 11,
	})

	r.Sleep()
	r.Disable()
}
```

**Expected output:**
```
Radio: Enable
Radio: Receive on channel 11
State: Receive
Caps: 0
EUI-64: 18B4300000000042
Radio: Transmit 3 bytes on channel 11
Radio: Sleep
Radio: Disable
```

---

## 4. Monitoring Network State

Read IPv6 addresses, neighbor table info, routing data, and leader data
from a running `Instance`.

```go
package main

import (
	"fmt"
	"time"

	"github.com/hilli/gothread/instance"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/routing"
)

func main() {
	plat := simulation.NewPlatform()
	inst := instance.New(instance.Config{
		Alarm:    plat.Alarm,
		Entropy:  plat.Entropy,
		Settings: plat.Settings,
		Logger:   plat.Logger,
		Radio:    plat.Radio,
	})

	inst.Start()
	time.Sleep(100 * time.Millisecond)

	// Query network state from the event loop.
	done := make(chan struct{})
	inst.PostTask(func() {
		defer close(done)

		// --- Device Role ---
		m := inst.MleService().Mle()
		fmt.Println("Device role:", m.Role())

		// --- Leader Data ---
		leader := m.GetLeaderData()
		fmt.Printf("Leader data:\n")
		fmt.Printf("  Partition ID:    %d\n", leader.PartitionID)
		fmt.Printf("  Weighting:       %d\n", leader.Weighting)
		fmt.Printf("  Data version:    %d\n", leader.DataVersion)
		fmt.Printf("  Leader router:   %d\n", leader.LeaderRouterID)

		// --- RLOC16 ---
		fmt.Printf("RLOC16: 0x%04X\n", inst.RLOC16())

		// --- IPv6 Unicast Addresses ---
		netif := inst.Netif()
		addrs := netif.GetUnicastAddresses()
		fmt.Printf("Unicast addresses (%d):\n", len(addrs))
		for _, addr := range addrs {
			fmt.Printf("  %s/%d rloc=%v meshlocal=%v\n",
				addr.Address.ToString(), addr.PrefixLength,
				addr.RLOC, addr.MeshLocal)
		}

		// --- Multicast Addresses ---
		maddrs := netif.GetMulticastAddresses()
		fmt.Printf("Multicast addresses (%d):\n", len(maddrs))
		for _, ma := range maddrs {
			fmt.Printf("  %s\n", ma.Address.ToString())
		}

		// --- Router Table ---
		rt := inst.RouterTable()
		fmt.Printf("Active routers: %d\n", rt.GetActiveRouterCount())

		// --- Neighbor Table ---
		nt := inst.NeighborTable()
		_ = nt // NeighborTable provides FindNeighborByShortAddress, etc.
		fmt.Println("Neighbor table initialized: true")
	})

	<-done
	inst.Stop()
	fmt.Println("Monitoring complete.")
}

// printNeighbor prints details about a routing.Neighbor.
func printNeighbor(n *routing.Neighbor) {
	fmt.Printf("  RLOC16: 0x%04X  State: %s  Age: %d\n",
		n.RLOC16, n.GetState(), n.Age)
}
```

**Expected output:**
```
Device role: Disabled
Leader data:
  Partition ID:    0
  Weighting:       0
  Data version:    0
  Leader router:   0
RLOC16: 0x0000
Unicast addresses (0):
Multicast addresses (0):
Active routers: 0
Neighbor table initialized: true
Monitoring complete.
```

---

## 5. Frame Inspection

Use `thread/mesh` types to build and parse raw IEEE 802.15.4 MAC frames.

```go
package main

import (
	"fmt"

	"github.com/hilli/gothread/mac/frame"
	"github.com/hilli/gothread/thread/mesh"
)

func main() {
	framer := mesh.NewFramer()

	// Build a MAC data frame with short addressing.
	ctx := &mesh.FrameContext{
		SrcShortAddr:   0x0001,
		DstShortAddr:   0xFFFF, // broadcast
		UseSrcShort:    true,
		UseDstShort:    true,
		PanId:          0xABCD,
		SequenceNumber: 42,
		AckRequest:     true,
	}

	payload := []byte("Hello Thread!")
	rawFrame, err := framer.BuildDataFrame(ctx, payload)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Built frame: %d bytes\n", len(rawFrame))
	fmt.Printf("Raw hex: %X\n", rawFrame)

	// Calculate header and max payload sizes.
	headerSize := framer.GetHeaderSize(ctx)
	maxPayload := framer.GetMaxPayloadSize(ctx)
	fmt.Printf("Header size: %d bytes\n", headerSize)
	fmt.Printf("Max payload: %d bytes\n", maxPayload)

	// Parse it back using the Framer.
	parsedCtx, payloadOffset, err := framer.ParseFrameHeader(rawFrame)
	if err != nil {
		panic(err)
	}
	fmt.Printf("\nParsed header (payload starts at byte %d):\n", payloadOffset)
	fmt.Printf("  Sequence number: %d\n", parsedCtx.SequenceNumber)
	fmt.Printf("  PAN ID:          0x%04X\n", parsedCtx.PanId)
	fmt.Printf("  Dst short addr:  0x%04X\n", parsedCtx.DstShortAddr)
	fmt.Printf("  Src short addr:  0x%04X\n", parsedCtx.SrcShortAddr)
	fmt.Printf("  Ack requested:   %v\n", parsedCtx.AckRequest)
	fmt.Printf("  Security:        %v\n", parsedCtx.SecurityEnabled)

	// Extract payload from raw frame.
	extractedPayload := rawFrame[payloadOffset:]
	fmt.Printf("  Payload:         %q\n", string(extractedPayload))

	// Also use mac/frame.Frame for low-level FCF inspection.
	f := frame.NewFrame(rawFrame)
	fmt.Printf("\nmac/frame inspection:\n")
	fmt.Printf("  Frame type:      %d (Data=%d)\n", f.GetType(), frame.TypeData)
	fmt.Printf("  Version:         0x%04X\n", f.GetVersion())
	fmt.Printf("  Security:        %v\n", f.IsSecurityEnabled())
	fmt.Printf("  Ack request:     %v\n", f.IsAckRequest())
	fmt.Printf("  Sequence:        %d\n", f.GetSequence())

	panID, _ := f.GetDstPanID()
	fmt.Printf("  Dst PAN ID:      0x%04X\n", panID)

	dstAddr, _ := f.GetDstAddr()
	fmt.Printf("  Dst addr type:   %v\n", f.GetDstAddrMode())
	_ = dstAddr

	hdrLen, _ := f.GetHeaderLength()
	fmt.Printf("  Header length:   %d\n", hdrLen)
}
```

**Expected output:**
```
Built frame: 22 bytes
Raw hex: 6188...
Header size: 9 bytes
Max payload: 116 bytes

Parsed header (payload starts at byte 9):
  Sequence number: 42
  PAN ID:          0xABCD
  Dst short addr:  0xFFFF
  Src short addr:  0x0001
  Ack requested:   true
  Security:        false
  Payload:         "Hello Thread!"

mac/frame inspection:
  Frame type:      1 (Data=1)
  Version:         0x1000
  Security:        false
  Ack request:     true
  Sequence:        42
  Dst PAN ID:      0xABCD
  Dst addr type:   Short
  Header length:   9
```

---

## 6. AES-CCM Security

Encrypt and decrypt a MAC data frame using IEEE 802.15.4 AES-CCM security
with `thread/mesh/security.go` and `crypto/aesccm`.

```go
package main

import (
	"bytes"
	"fmt"

	"github.com/hilli/gothread/crypto/aesccm"
	"github.com/hilli/gothread/thread/mesh"
)

func main() {
	framer := mesh.NewFramer()

	// 128-bit AES key.
	aesKey := [16]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
	}

	srcExtAddr := [8]byte{0x18, 0xB4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01}

	// Build a security-enabled frame context.
	ctx := &mesh.FrameContext{
		SrcExtAddr:      srcExtAddr,
		DstShortAddr:    0xFFFF,
		UseSrcShort:     false, // use extended source address
		UseDstShort:     true,
		PanId:           0xFACE,
		SequenceNumber:  7,
		SecurityEnabled: true,
		Security: mesh.SecurityMaterial{
			KeyIdMode:    1,
			KeyId:        1,
			Key:          aesKey,
			FrameCounter: 100,
		},
	}

	// Encrypt: BuildDataFrame applies AES-CCM internally.
	plaintext := []byte("Secure Thread Data")
	encFrame, err := framer.BuildDataFrame(ctx, plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Encrypted frame: %d bytes\n", len(encFrame))

	// Show nonce construction.
	nonce := mesh.BuildNonce(srcExtAddr, 100, uint8(mesh.SecurityEncMic32))
	fmt.Printf("Nonce (13 bytes): %X\n", nonce)

	// Parse the header to find the payload offset.
	parsedCtx, payloadOffset, err := framer.ParseFrameHeader(encFrame)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Security enabled: %v\n", parsedCtx.SecurityEnabled)
	fmt.Printf("Key ID mode:      %d\n", parsedCtx.Security.KeyIdMode)
	fmt.Printf("Frame counter:    %d\n", parsedCtx.Security.FrameCounter)

	// Decrypt using DecryptFramePayload.
	decrypted, err := mesh.DecryptFramePayload(
		encFrame, payloadOffset, parsedCtx, aesKey, srcExtAddr,
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Decrypted:        %q\n", string(decrypted))
	fmt.Printf("Match original:   %v\n", bytes.Equal(decrypted, plaintext))

	// Demonstrate raw AES-CCM usage.
	fmt.Println("\n--- Raw AES-CCM ---")
	var ccm aesccm.AesCcm
	if err := ccm.SetKey(aesKey[:]); err != nil {
		panic(err)
	}
	aad := []byte("additional-data")
	ct, tag, err := ccm.Seal(nonce[:], plaintext, aad, 4)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Ciphertext: %X\n", ct)
	fmt.Printf("Tag (4B):   %X\n", tag)

	pt, err := ccm.Open(nonce[:], ct, aad, tag)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Decrypted:  %q\n", string(pt))
}
```

**Expected output:**
```
Encrypted frame: 40 bytes
Nonce (13 bytes): 18B430000000000164000000050
Security enabled: true
Key ID mode:      1
Frame counter:    100
Decrypted:        "Secure Thread Data"
Match original:   true

--- Raw AES-CCM ---
Ciphertext: <hex bytes>
Tag (4B):   <hex bytes>
Decrypted:  "Secure Thread Data"
```

---

## 7. OpenThread Interop

Set up a `UDPSimRadio` to receive frames from an OpenThread simulation node
via UDP multicast. This radio implements the same UDP simulation protocol
used by OpenThread's `ot-cli-ftd` in simulation mode.

```go
package main

import (
	"fmt"
	"time"

	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/radio"
)

func main() {
	// Create a UDPSimRadio with node ID 2 (default port base 9000).
	// This binds to 127.0.0.1:9002 for TX and joins 224.0.0.116:9000 for RX.
	// OpenThread simulation nodes use the same multicast group.
	udpRadio, err := simulation.NewUDPSimRadio(2)
	if err != nil {
		panic(err)
	}

	// Set up a receive callback to handle incoming frames.
	frameCount := 0
	udpRadio.SetReceiveCallback(func(f *radio.Frame) {
		frameCount++
		fmt.Printf("Received frame #%d: channel=%d len=%d rssi=%d\n",
			frameCount, f.Channel, len(f.PSDU), f.RxInfo.RSSI)
	})

	// Start the radio (opens UDP sockets, begins receive loop).
	if err := udpRadio.Start(); err != nil {
		fmt.Printf("Start error (expected in non-simulation env): %v\n", err)
		fmt.Println("To test interop, run an OpenThread simulation node:")
		fmt.Println("  ./ot-cli-ftd 1  # node 1 on port 9001")
		fmt.Println("Then this program will receive its frames.")
		return
	}
	defer udpRadio.Stop()

	// Enable the radio and set it to receive on channel 11.
	udpRadio.Enable()
	udpRadio.Receive(11)

	fmt.Println("UDPSimRadio listening...")
	fmt.Printf("  Node ID:    %d\n", 2)
	fmt.Printf("  Port base:  %d\n", simulation.DefaultPortBase)
	fmt.Printf("  Multicast:  %s\n", simulation.SimMulticastAddr)
	fmt.Printf("  TX port:    %d\n", simulation.DefaultPortBase+2)
	fmt.Printf("  State:      %s\n", udpRadio.GetState())
	fmt.Printf("  EUI-64:     %X\n", udpRadio.GetIEEEEui64())

	// Transmit a test frame (will be multicast to 224.0.0.116:9000).
	txBuf := udpRadio.GetTransmitBuffer()
	txBuf.PSDU = []byte{0x41, 0x88, 0x01, 0xCD, 0xAB, 0xFF, 0xFF, 0x02, 0x00}
	txBuf.Channel = 11
	if err := udpRadio.Transmit(txBuf); err != nil {
		fmt.Printf("Transmit error: %v\n", err)
	} else {
		fmt.Println("Transmitted test frame via UDP multicast.")
	}

	// Wait for potential incoming frames.
	time.Sleep(2 * time.Second)

	fmt.Printf("Total frames received: %d\n", frameCount)

	// Demonstrate creating a radio with custom port base.
	customRadio, _ := simulation.NewUDPSimRadioWithPort(5, 10000)
	fmt.Printf("Custom radio EUI-64: %X\n", customRadio.GetIEEEEui64())
}
```

**Expected output** (standalone, no OT node running):
```
UDPSimRadio listening...
  Node ID:    2
  Port base:  9000
  Multicast:  224.0.0.116
  TX port:    9002
  State:      Receive
  EUI-64:     18B4300000000002
Transmitted test frame via UDP multicast.
Total frames received: 0
Custom radio EUI-64: 18B4300000000005
```

---

## 8. UDP Communication

Use the real instance executor and outbound hook, not
`UDPManager.HandleMessage` (ingress/local delivery). This function expects an
already running, attached instance with a valid direct neighbor. It does not
open an OS socket, fabricate a radio link, or establish a Matter session.
Use explicit assigned addresses and a context with the application's deadline.
See [native UDP limits](api-overview.md#external-executor-and-native-udp):
single-frame unicast is supported; general routes, fragmentation, and multicast
discovery are not.

```go
package example

import (
	"context"
	"errors"
	"sync/atomic"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/instance"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/udp"
)

func exchange(ctx context.Context, inst *instance.Instance, info ip6.MessageInfo, payload []byte) (response []byte, err error) {
	type packet struct {
		payload []byte
		info    ip6.MessageInfo
	}
	incoming := make(chan packet, 4)
	var dropped atomic.Uint64
	manager := inst.UDPManager() // Borrowed; access its mutable state only via Do.
	socket := &udp.Socket{}

	err = inst.Do(ctx, func() error {
		if err := manager.Open(socket, udp.NetifThreadInternal, func(data []byte, metadata *ip6.MessageInfo) {
			// This callback runs on the stack loop; never block it on an app read.
			copyInfo := *metadata
			if metadata.LinkInfo != nil {
				link := *metadata.LinkInfo
				copyInfo.LinkInfo = &link
			}
			snapshot := packet{payload: append([]byte(nil), data...), info: copyInfo}
			select {
			case incoming <- snapshot:
			default:
				dropped.Add(1)
			}
		}); err != nil {
			return err
		}
		if err := manager.Bind(socket, ip6.SockAddr{Address: info.SockAddr, Port: info.SockPort}); err != nil {
			return errors.Join(err, manager.Close(socket))
		}
		if err := manager.Connect(socket, ip6.SockAddr{Address: info.PeerAddr, Port: info.PeerPort}); err != nil {
			return errors.Join(err, manager.Close(socket))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		// Use a live cleanup context; a cancelled queued close would not execute.
		// Cleanup errors (including stopped/full executor) remain visible.
		err = errors.Join(err, inst.Do(context.Background(), func() error {
			return manager.Close(socket)
		}))
	}()

	if err := inst.Do(ctx, func() error { return inst.SendUDP(payload, info) }); err != nil {
		return nil, err
	}
	// Payload may now be reused. Nil above meant queue acceptance, not delivery.
	// Application parsing and reads happen outside the stack loop.
	select {
	case received := <-incoming:
		if dropped.Load() != 0 {
			return nil, goterrors.ErrNoBufs
		}
		return received.payload, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
```

No response is synthesized locally. A receive callback requires actual injected
or radio-delivered RX. Closing the UDP socket does not retract a datagram already
accepted for transmission, and this example's small receive queue is not an
application reliability or Matter MRP implementation. A production adapter must
surface queue overflow and cleanup errors to its owner.

---

## Notes

- All examples use `github.com/hilli/gothread` as the module path.
- The simulation platform (`platform/simulation`) provides in-memory
  implementations suitable for testing without hardware.
- `Medium` connects multiple `SimRadio` instances for in-process mesh
  simulation; `UDPSimRadio` connects to OpenThread's UDP simulation protocol.
- For a real deployment, replace simulation components with hardware-backed
  implementations of `radio.Radio`, `platform.Alarm`, `platform.Entropy`,
  `platform.Settings`, and `platform.Logger`.
