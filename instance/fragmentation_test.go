// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/udp"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/routing"
)

type fragmentRadio struct {
	*boundedUDPRadio
	identity [8]byte
	caps     radio.Caps
}

func (r *fragmentRadio) GetIEEEEui64() [8]byte { return r.identity }
func (r *fragmentRadio) GetCaps() radio.Caps   { return r.caps }

type fragmentDelivery struct {
	payload []byte
	info    ip6.MessageInfo
}

type fragmentEndpoint struct {
	inst      *Instance
	driver    *fragmentRadio
	incoming  chan fragmentDelivery
	macKey    [16]byte
	callbacks int
}

var fragmentSource = types.ExtAddress{0xa4, 0x17, 0x2b, 0xc3, 0x5d, 0xe6, 0x79, 0x80}

func newFragmentEndpoint(t *testing.T, identity, peer types.ExtAddress, rloc, peerRLOC uint16, settings platform.Settings) *fragmentEndpoint {
	return newFragmentEndpointCaps(t, identity, peer, rloc, peerRLOC, settings,
		radio.CapCsmaBackoff|radio.CapTransmitRetries|radio.CapAckTimeout)
}

func newFragmentEndpointCaps(t *testing.T, identity, peer types.ExtAddress, rloc, peerRLOC uint16, settings platform.Settings, caps radio.Caps) *fragmentEndpoint {
	t.Helper()
	driver := &fragmentRadio{
		boundedUDPRadio: &boundedUDPRadio{captures: make(chan udpRadioCapture, 2), settings: settings},
		identity:        identity,
		caps:            caps,
	}
	node := &fragmentEndpoint{
		inst: New(Config{Radio: driver, Settings: settings}), driver: driver,
		incoming: make(chan fragmentDelivery, 2),
	}
	if err := node.inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(node.inst.Stop)
	if err := node.inst.Do(context.Background(), func() error {
		node.inst.keyManager.SetNetworkKey(key.NetworkKey{1, 2, 3, 4, 5})
		node.inst.mac.SetPanID(0xface)
		node.inst.mac.SetPanChannel(20)
		if err := node.inst.IfConfigUp(); err != nil {
			return err
		}
		if err := node.inst.ThreadStart(); err != nil {
			return err
		}
		// Explicit synthetic established direct link, never a claim of RF
		// attachment. All subsequent I/O uses actual MAC/radio callbacks.
		if err := node.inst.mleService.Mle().SetStateRouter(rloc); err != nil {
			return err
		}
		node.inst.SetRLOC16(rloc)
		node.inst.mac.SetShortAddress(types.ShortAddress(rloc))
		node.inst.SetMeshLocalPrefix([8]byte{0xfd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77})
		router, err := node.inst.routerTable.AllocateWithID(uint8(peerRLOC >> 10))
		if err != nil {
			return err
		}
		router.ExtAddress, router.RLOC16 = peer, peerRLOC
		router.State = routing.StateValid
		router.Mode.Set(0x0f)
		router.LastHeard = uint32(time.Now().UnixMilli())
		node.macKey = node.inst.keyManager.GetCurrentMacKey()
		socket := &udp.Socket{}
		if err := node.inst.udpManager.Open(socket, udp.NetifThreadInternal, func(payload []byte, metadata *ip6.MessageInfo) {
			node.callbacks++
			copyInfo := *metadata
			if metadata.LinkInfo != nil {
				link := *metadata.LinkInfo
				copyInfo.LinkInfo = &link
			}
			select {
			case node.incoming <- fragmentDelivery{payload: append([]byte(nil), payload...), info: copyInfo}:
			default:
				t.Error("bounded application test queue overflowed")
			}
		}); err != nil {
			return err
		}
		return node.inst.udpManager.Bind(socket, ip6.SockAddr{Port: 5540})
	}); err != nil {
		t.Fatal(err)
	}
	return node
}

func fragmentInfo(src, dst types.ExtAddress, rloc bool) ip6.MessageInfo {
	info := ip6.MessageInfo{
		SockAddr: linkLocalAddress(src), PeerAddr: linkLocalAddress(dst),
		SockPort: 5540, PeerPort: 5540,
	}
	if rloc {
		info.SockAddr = ip6.Address{0xfd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 11: 0xff, 12: 0xfe, 14: 4}
		info.PeerAddr = info.SockAddr
		info.PeerAddr[14] = 8
	}
	return info
}

func nativeAdaptation(t *testing.T, capture udpRadioCapture, macKey [16]byte) (ctx *mesh.FrameContext, adaptation []byte) {
	t.Helper()
	ctx, n, err := mesh.NewFramer().ParseFrameHeader(capture.frame.PSDU)
	if err != nil {
		t.Fatal(err)
	}
	if !ctx.SecurityEnabled || ctx.UseSrcShort || ctx.UseDstShort || len(capture.frame.PSDU) > 125 {
		t.Fatalf("invalid actual secured MAC frame: %+v bytes=%d", ctx, len(capture.frame.PSDU))
	}
	plain, err := mesh.DecryptFramePayload(capture.frame.PSDU, n, ctx, macKey, ctx.SrcExtAddr)
	if err != nil {
		t.Fatal(err)
	}
	if len(capture.state) != 0 && ctx.Security.FrameCounter >= binary.BigEndian.Uint32(capture.state[37:41]) {
		t.Fatal("secured fragment preceded its durable counter reservation")
	}
	return ctx, plain
}

func deliverNativeFrame(t *testing.T, node *fragmentEndpoint, capture udpRadioCapture) {
	t.Helper()
	frame := capture.frame
	frame.PSDU = append([]byte(nil), frame.PSDU...)
	frame.RxInfo = &radio.RxInfo{RSSI: -37, LQI: 90}
	if err := node.inst.Do(context.Background(), func() error {
		node.inst.subMac.HandleReceiveDone(&frame, nil)
		clear(frame.PSDU) // The radio's receive buffer is borrowed.
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func completeNativeFrame(t *testing.T, node *fragmentEndpoint, completed udpRadioCapture, txErr error) {
	t.Helper()
	if err := node.inst.Do(context.Background(), func() error {
		node.inst.subMac.HandleTransmitDone(&completed.frame, nil, txErr)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	waitUDPCondition(t, node.inst, func() bool {
		return node.inst.pendingTxMsg == nil || len(node.driver.captures) != 0
	})
}

func sendNativeDatagram(t *testing.T, src, dst *fragmentEndpoint, payload []byte, info ip6.MessageInfo, firstLate bool) []udpRadioCapture {
	t.Helper()
	if err := src.inst.Do(context.Background(), func() error { return src.inst.SendUDP(payload, info) }); err != nil {
		t.Fatal(err)
	}
	var frames []udpRadioCapture
	var lastCounter uint32
	for {
		capture := captureUDP(t, src.driver.boundedUDPRadio)
		ctx, adaptation := nativeAdaptation(t, capture, src.macKey)
		if len(frames) != 0 && ctx.Security.FrameCounter != lastCounter+1 {
			t.Fatalf("distinct fragments reused/skipped counter: %d -> %d", lastCounter, ctx.Security.FrameCounter)
		}
		lastCounter = ctx.Security.FrameCounter
		frames = append(frames, capture)
		if !firstLate {
			deliverNativeFrame(t, dst, capture)
			if adaptation[0]&0xf8 == 0xc0 || adaptation[0]&0xf8 == 0xe0 {
				deliverNativeFrame(t, dst, capture) // Exact duplicate fragment.
			}
		}
		completeNativeFrame(t, src, capture, nil)
		var usage mesh.BufferUsage
		if err := src.inst.Do(context.Background(), func() error { usage = src.inst.forwarder.GetBufferUsage(); return nil }); err != nil {
			t.Fatal(err)
		}
		if usage.TxDatagrams == 0 {
			break
		}
		if len(frames) > 40 {
			t.Fatal("fragmented datagram did not retire within its bounded plan")
		}
	}
	if firstLate {
		for i := len(frames) - 1; i >= 0; i-- {
			deliverNativeFrame(t, dst, frames[i])
			if len(frames) > 1 {
				deliverNativeFrame(t, dst, frames[i])
			}
		}
	}
	return frames
}

func assertFragmentDelivery(t *testing.T, src, dst *fragmentEndpoint, payload []byte, info ip6.MessageInfo, expected int) {
	t.Helper()
	select {
	case packet := <-dst.incoming:
		hop := info.HopLimit
		if hop == 0 {
			hop = 64
		}
		if !bytes.Equal(packet.payload, payload) || packet.info.SockAddr != info.PeerAddr ||
			packet.info.PeerAddr != info.SockAddr || packet.info.SockPort != info.PeerPort ||
			packet.info.PeerPort != info.SockPort || packet.info.HopLimit != hop {
			t.Fatalf("real datagram tuple/payload mismatch: %+v bytes=%d", packet.info, len(packet.payload))
		}
	default:
		if err := dst.inst.Do(context.Background(), func() error {
			t.Errorf("no datagram delivered: counters=%+v buffers=%+v", dst.inst.forwarder.GetCounters(), dst.inst.forwarder.GetBufferUsage())
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := dst.inst.Do(context.Background(), func() error {
		if dst.callbacks != expected || dst.inst.forwarder.GetBufferUsage().RxBytes != 0 {
			t.Errorf("duplicate delivery or retained RX buffers: calls=%d want=%d buffers=%+v", dst.callbacks, expected, dst.inst.forwarder.GetBufferUsage())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := src.inst.Do(context.Background(), func() error {
		if src.callbacks != 0 || src.inst.forwarder.GetBufferUsage().TxBytes != 0 {
			t.Error("local reinjection or retained TX buffer")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStandardFragmentedMTUTwoRealInstances(t *testing.T) {
	for _, rloc := range []bool{false, true} {
		for _, firstLate := range []bool{false, true} {
			t.Run(fmt.Sprintf("rloc=%v/first-late=%v", rloc, firstLate), func(t *testing.T) {
				src := newFragmentEndpoint(t, fragmentSource, udpPeerExt, 0x0400, 0x0800, simulation.NewSimSettings())
				dst := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
				info := fragmentInfo(fragmentSource, udpPeerExt, rloc)
				for index, size := range []int{0, 1, 53, 54, 59, 85, 86, 92, 98, 131, 174, 1231, 1232} {
					payload := make([]byte, size)
					for i := range payload {
						payload[i] = byte(i*17 + 3)
					}
					frames := sendNativeDatagram(t, src, dst, payload, info, firstLate)
					assertFragmentDelivery(t, src, dst, payload, info, index+1)
					if size == 1232 && len(frames) != 15 {
						t.Fatalf("MTU1280 used %d frames, want 15 with these headers", len(frames))
					}
					// Even replaying the complete fragmented datagram cannot
					// produce another callback within the bounded tag cache.
					if len(frames) > 1 {
						for _, frame := range frames {
							deliverNativeFrame(t, dst, frame)
						}
						if err := dst.inst.Do(context.Background(), func() error {
							if dst.callbacks != index+1 {
								t.Error("complete fragmented replay delivered twice")
							}
							return nil
						}); err != nil {
							t.Fatal(err)
						}
					}
				}
				if err := src.inst.Do(context.Background(), func() error {
					before := src.inst.forwarder.GetBufferUsage()
					counter := src.inst.keyManager.GetMacFrameCounter()
					if err := src.inst.SendUDP(make([]byte, 1233), info); err != goterrors.ErrNoBufs {
						t.Errorf("1233-byte application admission=%v", err)
					}
					if src.inst.forwarder.GetBufferUsage() != before || src.inst.keyManager.GetMacFrameCounter() != counter {
						t.Error("oversize refusal changed buffers or counters")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestStandardFragmentationLiteralRFCCoordinateFixture(t *testing.T) {
	dst := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
	// Independently specified RFC fixture, not produced by our fragmenter.
	// Uncompressed IPv6 size=134, tag=0x1234, FRAGN offset=128/8.
	first := []byte{0xc0, 0x86, 0x12, 0x34, 0x7e, 0x33, 0xf0, 0x15, 0xa4, 0x15, 0xa4, 0x61, 0x41}
	for i := byte(0); i < 80; i++ {
		first = append(first, i)
	}

	finishLiteralRFCFixture(t, dst, first)
}

func TestStandardFragmentedRetryReusesOnlyTheSameMACFrame(t *testing.T) {
	src := newFragmentEndpointCaps(t, fragmentSource, udpPeerExt, 0x0400, 0x0800,
		simulation.NewSimSettings(), radio.CapCsmaBackoff|radio.CapAckTimeout)
	dst := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
	info := fragmentInfo(fragmentSource, udpPeerExt, false)
	payload := bytes.Repeat([]byte{0x3c}, 98)
	if err := src.inst.Do(context.Background(), func() error { return src.inst.SendUDP(payload, info) }); err != nil {
		t.Fatal(err)
	}
	first := captureUDP(t, src.driver.boundedUDPRadio)
	firstCtx, _ := nativeAdaptation(t, first, src.macKey)
	deliverNativeFrame(t, dst, first)
	completeNativeFrame(t, src, first, submac.ErrNoAck)
	retry := captureUDP(t, src.driver.boundedUDPRadio)
	retryCtx, _ := nativeAdaptation(t, retry, src.macKey)
	if !bytes.Equal(first.frame.PSDU, retry.frame.PSDU) ||
		firstCtx.Security.FrameCounter != retryCtx.Security.FrameCounter {
		t.Fatal("retry rebuilt a distinct frame or changed its nonce/counter")
	}
	deliverNativeFrame(t, dst, retry)
	completeNativeFrame(t, src, retry, nil)
	last := captureUDP(t, src.driver.boundedUDPRadio)
	lastCtx, _ := nativeAdaptation(t, last, src.macKey)
	if lastCtx.Security.FrameCounter != firstCtx.Security.FrameCounter+1 {
		t.Fatal("distinct next fragment did not allocate a fresh counter")
	}
	deliverNativeFrame(t, dst, last)
	completeNativeFrame(t, src, last, nil)
	assertFragmentDelivery(t, src, dst, payload, info, 1)
}

func TestStandardFragmentedPartialNoAckAndImmediateFailureRelease(t *testing.T) {
	src := newFragmentEndpoint(t, fragmentSource, udpPeerExt, 0x0400, 0x0800, simulation.NewSimSettings())
	dst := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
	info := fragmentInfo(fragmentSource, udpPeerExt, false)
	if err := src.inst.Do(context.Background(), func() error { return src.inst.SendUDP(make([]byte, 1232), info) }); err != nil {
		t.Fatal(err)
	}
	first := captureUDP(t, src.driver.boundedUDPRadio)
	deliverNativeFrame(t, dst, first)
	completeNativeFrame(t, src, first, nil)
	failed := captureUDP(t, src.driver.boundedUDPRadio)
	completeNativeFrame(t, src, failed, submac.ErrNoAck)
	if err := src.inst.Do(context.Background(), func() error {
		if src.inst.forwarder.GetBufferUsage().TxBytes != 0 || src.inst.forwarder.GetCounters().TxDropped != 1 {
			t.Error("final noACK did not retire the whole partial datagram")
		}
		src.driver.txErr = goterrors.ErrBusy
		return src.inst.SendUDP(make([]byte, 1232), info)
	}); err != nil {
		t.Fatal(err)
	}
	waitUDPCondition(t, src.inst, func() bool {
		return src.inst.forwarder.GetCounters().TxDropped == 2 &&
			src.inst.forwarder.GetBufferUsage().TxBytes == 0
	})
	if err := dst.inst.Do(context.Background(), func() error {
		if dst.callbacks != 0 || dst.inst.forwarder.GetBufferUsage().RxBytes != 1280 {
			t.Error("partial RF delivery either dispatched or lost its bounded incomplete state")
		}
		// The receiver cannot know the sender's MAC failure; disassociation or
		// expiry, not a fictional RF transaction, releases its partial packet.
		return dst.inst.ThreadStop()
	}); err != nil {
		t.Fatal(err)
	}
	if err := dst.inst.Do(context.Background(), func() error {
		if dst.inst.forwarder.GetBufferUsage().RxBytes != 0 {
			t.Error("ThreadStop retained incomplete RX buffers")
		}
		if err := dst.inst.ThreadStart(); err != nil {
			return err
		}
		return dst.inst.mleService.Mle().SetStateRouter(0x0800)
	}); err != nil {
		t.Fatal(err)
	}
	if err := src.inst.Do(context.Background(), func() error { src.driver.txErr = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x19}, 174)
	sendNativeDatagram(t, src, dst, payload, info, true)
	assertFragmentDelivery(t, src, dst, payload, info, 1)
}

func TestStandardFragmentedStopRestartAndInterfaceDisableRelease(t *testing.T) {
	src := newFragmentEndpoint(t, fragmentSource, udpPeerExt, 0x0400, 0x0800, simulation.NewSimSettings())
	dst := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
	info := fragmentInfo(fragmentSource, udpPeerExt, false)
	if err := src.inst.Do(context.Background(), func() error { return src.inst.SendUDP(make([]byte, 1232), info) }); err != nil {
		t.Fatal(err)
	}
	first := captureUDP(t, src.driver.boundedUDPRadio)
	deliverNativeFrame(t, dst, first)
	src.inst.Stop()
	dst.inst.Stop()
	if src.inst.forwarder.GetBufferUsage().TxBytes != 0 || dst.inst.forwarder.GetBufferUsage().RxBytes != 0 {
		t.Fatal("event-loop stop retained a partial TX/RX datagram")
	}
	if err := src.inst.Start(); err != nil {
		t.Fatal(err)
	}
	if err := dst.inst.Start(); err != nil {
		t.Fatal(err)
	}
	// Stop cannot retract a frame already given to a radio. Its completion
	// must be harmless and must not revive the discarded fragment sequence.
	completeNativeFrame(t, src, first, nil)
	payload := bytes.Repeat([]byte{0x28}, 131)
	sendNativeDatagram(t, src, dst, payload, info, false)
	assertFragmentDelivery(t, src, dst, payload, info, 1)
	if err := src.inst.Do(context.Background(), func() error {
		for range 4 {
			if err := src.inst.SendUDP(make([]byte, 1232), info); err != nil {
				return err
			}
		}
		before := src.inst.forwarder.GetBufferUsage()
		if before.TxBytes != mesh.MaxPendingDatagramBytes || before.TxFragments != 60 {
			t.Errorf("maximum datagram budget=%+v", before)
		}
		counter := src.inst.keyManager.GetMacFrameCounter()
		if err := src.inst.SendUDP(make([]byte, 1232), info); err != mesh.ErrQueueFull {
			t.Errorf("whole-datagram queue pressure=%v", err)
		}
		if src.inst.keyManager.GetMacFrameCounter() != counter || src.inst.forwarder.GetBufferUsage() != before {
			t.Error("rejected admission consumed counters or resource state")
		}
		if err := src.inst.ThreadStop(); err != nil {
			return err
		}
		return src.inst.IfConfigDown()
	}); err != nil {
		t.Fatal(err)
	}
	if err := src.inst.Do(context.Background(), func() error {
		if usage := src.inst.forwarder.GetBufferUsage(); usage != (mesh.BufferUsage{}) {
			t.Errorf("interface disable retained resources: %+v", usage)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStandardFragmentedPersistenceFailureAndFreshInstance(t *testing.T) {
	settings := &udpFaultSettings{SimSettings: simulation.NewSimSettings()}
	src := newFragmentEndpoint(t, fragmentSource, udpPeerExt, 0x0400, 0x0800, settings)
	dst := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
	info := fragmentInfo(fragmentSource, udpPeerExt, false)
	if err := src.inst.Do(context.Background(), func() error {
		if err := src.inst.SendUDP(make([]byte, 1232), info); err != nil {
			return err
		}
		return src.inst.SendUDP([]byte{1}, info)
	}); err != nil {
		t.Fatal(err)
	}
	first := captureUDP(t, src.driver.boundedUDPRadio)
	firstCtx, _ := nativeAdaptation(t, first, src.macKey)
	deliverNativeFrame(t, dst, first)
	writeErr := errors.New("injected fragment reservation failure")
	if err := src.inst.Do(context.Background(), func() error {
		// Force the existing reservation boundary, not a new storage profile.
		src.inst.keyManager.SetMacFrameCounter(src.inst.keyManager.GetStoredMacFrameCounter())
		settings.fail = writeErr
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	completeNativeFrame(t, src, first, nil)
	waitUDPCondition(t, src.inst, func() bool {
		return src.inst.forwarder.GetBufferUsage().TxBytes == 0
	})
	if err := src.inst.Do(context.Background(), func() error {
		if !errors.Is(src.inst.PersistenceError(), writeErr) ||
			src.inst.forwarder.GetCounters().TxDropped != 2 {
			t.Error("fragment persistence failure was hidden or retained pending datagrams")
		}
		if err := src.inst.SendUDP(nil, info); !errors.Is(err, writeErr) {
			t.Errorf("persistence failure admission identity=%v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	src.inst.Stop()
	settings.fail = nil
	fresh := newFragmentEndpoint(t, fragmentSource, udpPeerExt, 0x0400, 0x0800, settings)
	payload := bytes.Repeat([]byte{0x91}, 1232)
	frames := sendNativeDatagram(t, fresh, dst, payload, info, true)
	firstFresh, _ := nativeAdaptation(t, frames[0], fresh.macKey)
	if firstFresh.Security.FrameCounter <= firstCtx.Security.FrameCounter ||
		firstFresh.Security.FrameCounter < key.FrameCounterReservation {
		t.Fatal("fresh instance reused a pre-crash fragment counter/reservation")
	}
	select {
	case packet := <-dst.incoming:
		if !bytes.Equal(packet.payload, payload) {
			t.Fatal("fresh fragment tag merged with a pre-crash partial datagram")
		}
	default:
		t.Fatal("fresh instance's fragmented datagram did not arrive")
	}
	if err := dst.inst.Do(context.Background(), func() error {
		if dst.callbacks != 1 {
			t.Error("partial failure or reboot duplicated application delivery")
		}
		return dst.inst.ThreadStop()
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStandardFragmentedMalformedAuthenticatedFrames(t *testing.T) {
	for _, kind := range []string{"truncated-first", "truncated-fragn", "zero-checksum", "bad-checksum", "size-mismatch", "overlap", "bad-mic"} {
		t.Run(kind, func(t *testing.T) {
			dst := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
			first := []byte{0xc0, 0x86, 0x12, 0x34, 0x7e, 0x33, 0xf0, 0x15, 0xa4, 0x15, 0xa4, 0x61, 0x41}
			for i := byte(0); i < 80; i++ {
				first = append(first, i)
			}
			last := []byte{0xe0, 0x86, 0x12, 0x34, 0x10, 80, 81, 82, 83, 84, 85}
			wrap := func(data []byte, counter uint32) udpRadioCapture {
				ctx := &mesh.FrameContext{
					SrcExtAddr: fragmentSource, DstExtAddr: udpPeerExt, PanId: 0xface,
					SecurityEnabled: true,
					Security:        mesh.SecurityMaterial{Key: dst.macKey, KeyIdMode: 1, FrameCounter: counter},
				}
				psdu, err := mesh.NewFramer().BuildDataFrame(ctx, data)
				if err != nil {
					t.Fatal(err)
				}
				return udpRadioCapture{frame: radio.Frame{PSDU: psdu, Channel: 20}}
			}
			deliverNativeFrame(t, dst, wrap(last, 71))
			bad := append([]byte(nil), first...)
			switch kind {
			case "truncated-first":
				bad = bad[:12]
			case "truncated-fragn":
				bad = last[:4]
			case "zero-checksum":
				bad[11], bad[12] = 0, 0
			case "bad-checksum":
				bad[20] ^= 0xff
			case "size-mismatch":
				bad[1] += 8
			case "overlap":
				// Last fragment 128..134 is already present; this claims
				// 120..134 and conflicts with the earlier range.
				bad = append([]byte{0xe0, 0x86, 0x12, 0x34, 15}, make([]byte, 14)...)
			}
			capture := wrap(bad, 70)
			if kind == "bad-mic" {
				capture.frame.PSDU[len(capture.frame.PSDU)-1] ^= 1
			}
			deliverNativeFrame(t, dst, capture)
			if err := dst.inst.Do(context.Background(), func() error {
				if dst.callbacks != 0 || dst.inst.forwarder.GetCounters().RxDropped == 0 {
					t.Error("malformed fragment was delivered or not observable")
				}
				if kind != "bad-mic" && dst.inst.forwarder.GetBufferUsage().RxBytes != 0 {
					t.Error("identified malformed datagram retained its RX buffer")
				}
				return dst.inst.ThreadStop()
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func finishLiteralRFCFixture(t *testing.T, dst *fragmentEndpoint, first []byte) {
	last := []byte{0xe0, 0x86, 0x12, 0x34, 0x10, 80, 81, 82, 83, 84, 85}
	wrap := func(adaptation []byte, counter uint32) udpRadioCapture {
		ctx := &mesh.FrameContext{
			SrcExtAddr: fragmentSource, DstExtAddr: udpPeerExt, PanId: 0xface,
			SecurityEnabled: true,
			Security:        mesh.SecurityMaterial{Key: dst.macKey, KeyIdMode: 1, FrameCounter: counter},
		}
		frame, err := mesh.NewFramer().BuildDataFrame(ctx, adaptation)
		if err != nil {
			t.Fatal(err)
		}
		return udpRadioCapture{frame: radio.Frame{PSDU: frame, Channel: 20}}
	}
	deliverNativeFrame(t, dst, wrap(last, 71)) // FRAGN arrives before FRAG1.
	deliverNativeFrame(t, dst, wrap(first, 70))
	select {
	case packet := <-dst.incoming:
		if len(packet.payload) != 86 {
			t.Fatalf("literal fixture payload=%d", len(packet.payload))
		}
		for i, value := range packet.payload {
			if value != byte(i) {
				t.Fatalf("literal fixture byte[%d]=%d", i, value)
			}
		}
	default:
		t.Fatal("literal uncompressed-offset fixture did not traverse real RX")
	}
	deliverNativeFrame(t, dst, wrap(last, 71))
	deliverNativeFrame(t, dst, wrap(first, 70))
	if err := dst.inst.Do(context.Background(), func() error {
		if dst.callbacks != 1 {
			t.Error("literal RFC fixture duplicated delivery")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
