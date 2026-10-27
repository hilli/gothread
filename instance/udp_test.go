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
	"runtime"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/udp"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/lowpan"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/routing"
)

type udpRadioCapture struct {
	frame radio.Frame
	state []byte
}

type boundedUDPRadio struct {
	nopRadio
	captures   chan udpRadioCapture
	settings   platform.Settings
	txErr      error
	lastSubmit *radio.Frame
}

func (r *boundedUDPRadio) GetIEEEEui64() [8]byte {
	return [8]byte{0xa4, 0x17, 0x2b, 0xc3, 0x5d, 0xe6, 0x79, 0x80}
}

func (*boundedUDPRadio) GetCaps() radio.Caps {
	return radio.CapCsmaBackoff | radio.CapTransmitRetries | radio.CapAckTimeout
}

func (r *boundedUDPRadio) Transmit(frame *radio.Frame) error {
	r.lastSubmit = frame
	if r.txErr != nil {
		return r.txErr
	}
	capture := udpRadioCapture{frame: *frame}
	capture.frame.PSDU = append([]byte(nil), frame.PSDU...)
	if frame.TxInfo != nil {
		info := *frame.TxInfo
		capture.frame.TxInfo = &info
	}
	if r.settings != nil {
		var err error
		capture.state, err = r.settings.Get(platform.SettingsKeyNetworkInfo, 0)
		if err != nil {
			return err
		}
	}
	select {
	case r.captures <- capture:
		return nil
	default:
		return goterrors.ErrBusy
	}
}

var udpPeerExt = types.ExtAddress{0x18, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}

func newReadyUDPInstance(t *testing.T, settings platform.Settings) (*Instance, *boundedUDPRadio, ip6.MessageInfo) {
	t.Helper()
	r := &boundedUDPRadio{captures: make(chan udpRadioCapture, 2), settings: settings}
	inst := New(Config{Radio: r, Settings: settings})
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(inst.Stop)
	info := ip6.MessageInfo{SockPort: 5540, PeerPort: 5540}
	err := inst.Do(context.Background(), func() error {
		inst.keyManager.SetNetworkKey(key.NetworkKey{1, 2, 3, 4, 5})
		if err := inst.IfConfigUp(); err != nil {
			return err
		}
		if err := inst.ThreadStart(); err != nil {
			return err
		}
		// Supply an established direct link without claiming RF attachment.
		// Exercise all subsequent TX/RX through the actual Instance/MAC.
		if err := inst.mleService.Mle().SetStateRouter(0x0400); err != nil {
			return err
		}
		inst.SetRLOC16(0x0400)
		inst.SetMeshLocalPrefix([8]byte{0xfd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77})
		neighbor, err := inst.routerTable.AllocateWithID(2)
		if err != nil {
			return err
		}
		neighbor.ExtAddress = udpPeerExt
		neighbor.State = routing.StateValid
		neighbor.Mode.Set(0x0f)
		info.SockAddr = inst.GetLinkLocalAddress()
		info.PeerAddr = linkLocalAddress(udpPeerExt)
		return inst.PersistenceError()
	})
	if err != nil {
		t.Fatal(err)
	}
	return inst, r, info
}

func captureUDP(t *testing.T, r *boundedUDPRadio) udpRadioCapture {
	t.Helper()
	select {
	case frame := <-r.captures:
		return frame
	case <-time.After(5 * time.Second):
		t.Fatal("no real outbound Radio.Transmit call")
		return udpRadioCapture{}
	}
}

func decodeUDP(t *testing.T, frame *radio.Frame, macKey [16]byte) (info ip6.MessageInfo, payload []byte, counter uint32) {
	t.Helper()
	ctx, offset, err := mesh.NewFramer().ParseFrameHeader(frame.PSDU)
	if err != nil {
		t.Fatal(err)
	}
	if !ctx.SecurityEnabled || ctx.UseSrcShort || ctx.UseDstShort {
		t.Fatal("expected secured direct frame with explicit extended MAC addresses")
	}
	data, err := mesh.DecryptFramePayload(frame.PSDU, offset, ctx, macKey, ctx.SrcExtAddr)
	if err != nil {
		t.Fatal(err)
	}
	if lowpan.IsFragment(data) {
		t.Fatal("single-frame API emitted an unexpected fragment")
	}
	header, n, compressed, err := lowpan.DecompressHeader(data, lowpan.AddressContext{
		SrcExtAddr: ctx.SrcExtAddr, DstExtAddr: ctx.DstExtAddr,
	}, nil)
	if err != nil || !compressed {
		t.Fatalf("decompress IPv6: compressed=%v, error=%v", compressed, err)
	}
	hdr := ip6.HeaderFromBytes(header)
	udpHeader, consumed, err := lowpan.DecompressUDPHeader(data[n:])
	if err != nil {
		t.Fatal(err)
	}
	payload = data[n+consumed:]
	info = ip6.MessageInfo{
		SockAddr: hdr.GetSource(), PeerAddr: hdr.GetDestination(), HopLimit: hdr.GetHopLimit(),
		SockPort: binary.BigEndian.Uint16(udpHeader[:2]), PeerPort: binary.BigEndian.Uint16(udpHeader[2:4]),
	}
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(ip6.UDPHeaderSize+len(payload)))
	if binary.BigEndian.Uint16(udpHeader[6:]) == 0 {
		t.Fatal("IPv6 UDP checksum was neither computed nor transmitted")
	}
	// Verify using an independent one's-complement implementation and the
	// decompressed wire addresses, rather than the TX checksum helper.
	pseudo := append([]byte(nil), info.SockAddr[:]...)
	pseudo = append(pseudo, info.PeerAddr[:]...)
	pseudo = append(pseudo, 0, 0, udpHeader[4], udpHeader[5], 0, 0, 0, ip6.ProtoUDP)
	pseudo = append(pseudo, udpHeader[:]...)
	pseudo = append(pseudo, payload...)
	if len(pseudo)%2 != 0 {
		pseudo = append(pseudo, 0)
	}
	var sum uint32
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	if sum != 0xffff {
		t.Fatalf("invalid IPv6 UDP checksum sum=0x%x", sum)
	}
	return info, payload, ctx.Security.FrameCounter
}

func TestSendUDPRealOutboundOwnsPayloadAndNeverReinjects(t *testing.T) {
	inst, r, info := newReadyUDPInstance(t, simulation.NewSimSettings())
	input := []byte{1, 3, 5, 7, 9}
	want := append([]byte(nil), input...)
	var macKey [16]byte
	var received int
	socket := &udp.Socket{}
	if err := inst.Do(context.Background(), func() error {
		if err := inst.udpManager.Open(socket, udp.NetifThreadInternal, func([]byte, *ip6.MessageInfo) { received++ }); err != nil {
			return err
		}
		if err := inst.udpManager.Bind(socket, ip6.SockAddr{Address: info.SockAddr, Port: info.SockPort}); err != nil {
			return err
		}
		macKey = inst.keyManager.GetCurrentMacKey()
		if err := inst.SendUDP(input, info); err != nil {
			return err
		}
		// Reuse after acceptance, before yielding to the actual MAC tasklet.
		for i := range input {
			input[i] = 0xff
		}
		info.PeerPort = 9999
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for i := range input {
		input[i] = 0xee
	}
	captured := captureUDP(t, r)
	gotInfo, got, counter := decodeUDP(t, &captured.frame, macKey)
	if !bytes.Equal(got, want) || gotInfo.SockAddr != info.SockAddr ||
		gotInfo.PeerAddr != info.PeerAddr || gotInfo.SockPort != 5540 || gotInfo.PeerPort != 5540 || gotInfo.HopLimit != 64 {
		t.Fatalf("outbound info/payload changed: %+v %x", gotInfo, got)
	}
	if captured.frame.TxInfo == nil || !captured.frame.TxInfo.IsSecurityProcessed ||
		!captured.frame.TxInfo.CsmaCaEnabled {
		t.Fatal("normal software-security/CSMA metadata was not propagated")
	}
	if len(captured.state) != 49 || counter >= binary.BigEndian.Uint32(captured.state[37:41]) {
		t.Fatal("outbound frame preceded durable MAC counter reservation")
	}
	if err := inst.Do(context.Background(), func() error {
		if received != 0 {
			t.Error("outbound send was locally reinjected")
		}
		if inst.keyManager.GetMacFrameCounter() != counter+1 {
			t.Error("outbound send did not use normal frame-counter allocation")
		}
		inst.subMac.HandleTransmitDone(&captured.frame, nil, nil)
		return inst.udpManager.Close(socket)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSendUDPSupportedRoutesHopLimitsAndExactBounds(t *testing.T) {
	for _, meshLocal := range []bool{false, true} {
		for _, hopLimit := range []uint8{0, 1, 42, 64, 255} {
			t.Run(fmt.Sprintf("hop=%d/mesh-local=%v", hopLimit, meshLocal), func(t *testing.T) {
				inst, r, info := newReadyUDPInstance(t, nil)
				var macKey [16]byte
				maxPayload := 85 // Extended/extended MAC, elided LL IPHC, full UDP ports.
				if meshLocal {
					maxPayload = 53 // Both full mesh-local IPv6 addresses are inline.
				}
				if hopLimit == 42 {
					maxPayload--
				}
				info.HopLimit = hopLimit
				if err := inst.Do(context.Background(), func() error {
					if meshLocal {
						info.SockAddr = inst.GetMeshLocalAddress()
						info.PeerAddr = info.SockAddr
						iid := info.PeerAddr.GetIid()
						iid.SetLocator(0x0800)
						copy(info.PeerAddr[8:], iid[:])
					}
					macKey = inst.keyManager.GetCurrentMacKey()
					probe := inst.newUDPMessage(make([]byte, maxPayload+1), info)
					probe.Metadata.UseSrcShort, probe.Metadata.UseDstShort = false, false
					probe.Metadata.DstExtAddr = udpPeerExt
					if err := mesh.ValidateTxFrame(probe); err != goterrors.ErrNoBufs {
						t.Errorf("single-frame threshold=%v, want ErrNoBufs", err)
					}
					return inst.SendUDP(bytes.Repeat([]byte{0xa5}, maxPayload), info)
				}); err != nil {
					t.Fatal(err)
				}
				captured := captureUDP(t, r)
				gotInfo, payload, _ := decodeUDP(t, &captured.frame, macKey)
				wantHop := hopLimit
				if wantHop == 0 {
					wantHop = 64
				}
				if gotInfo.SockAddr != info.SockAddr || gotInfo.PeerAddr != info.PeerAddr ||
					gotInfo.HopLimit != wantHop || len(payload) != maxPayload || len(captured.frame.PSDU) != mesh.MaxPsduSize-mesh.FCSSize {
					t.Fatalf("exact frame/UDP limit mismatch: info=%+v payload=%d frame=%d", gotInfo, len(payload), len(captured.frame.PSDU))
				}
			})
		}
	}
}

func TestSendUDPZeroPayloadAndQueuedBurst(t *testing.T) {
	inst, r, info := newReadyUDPInstance(t, nil)
	var macKey [16]byte
	if err := inst.Do(context.Background(), func() error {
		macKey = inst.keyManager.GetCurrentMacKey()
		if err := inst.SendUDP(nil, info); err != nil {
			return err
		}
		return inst.SendUDP([]byte{42}, info)
	}); err != nil {
		t.Fatal(err)
	}
	first := captureUDP(t, r)
	_, data, firstCounter := decodeUDP(t, &first.frame, macKey)
	if len(data) != 0 {
		t.Fatalf("zero datagram carried %x", data)
	}
	if err := inst.Do(context.Background(), func() error {
		inst.subMac.HandleTransmitDone(&first.frame, nil, nil)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	second := captureUDP(t, r)
	_, data, counter := decodeUDP(t, &second.frame, macKey)
	if !bytes.Equal(data, []byte{42}) || counter != firstCounter+1 {
		t.Fatalf("queued burst not transmitted with fresh counter: %x %d/%d", data, firstCounter, counter)
	}
}

func TestSendUDPCompressedPortBounds(t *testing.T) {
	for _, ports := range []struct {
		src, dst uint16
		max      int
	}{
		{0xf0b1, 0xf0bf, 88},
		{5540, 0xf001, 86},
		{0xf001, 5540, 86},
	} {
		t.Run(fmt.Sprintf("%d-%d", ports.src, ports.dst), func(t *testing.T) {
			inst, r, info := newReadyUDPInstance(t, nil)
			info.SockPort, info.PeerPort = ports.src, ports.dst
			var macKey [16]byte
			if err := inst.Do(context.Background(), func() error {
				macKey = inst.keyManager.GetCurrentMacKey()
				probe := inst.newUDPMessage(make([]byte, ports.max+1), info)
				probe.Metadata.UseSrcShort, probe.Metadata.UseDstShort = false, false
				probe.Metadata.DstExtAddr = udpPeerExt
				if err := mesh.ValidateTxFrame(probe); err != goterrors.ErrNoBufs {
					t.Errorf("compressed-port single-frame threshold=%v", err)
				}
				return inst.SendUDP(make([]byte, ports.max), info)
			}); err != nil {
				t.Fatal(err)
			}
			frame := captureUDP(t, r)
			got, payload, _ := decodeUDP(t, &frame.frame, macKey)
			if got.SockPort != ports.src || got.PeerPort != ports.dst || len(payload) != ports.max ||
				len(frame.frame.PSDU) != mesh.MaxPsduSize-mesh.FCSSize {
				t.Fatalf("compressed-port limits: %+v payload=%d frame=%d", got, len(payload), len(frame.frame.PSDU))
			}
		})
	}
}

func TestSendUDPAdmissionValidation(t *testing.T) {
	inst, _, valid := newReadyUDPInstance(t, nil)
	tests := []struct {
		name string
		edit func(*ip6.MessageInfo)
		want error
	}{
		{"source-port", func(i *ip6.MessageInfo) { i.SockPort = 0 }, goterrors.ErrInvalidArgs},
		{"peer-port", func(i *ip6.MessageInfo) { i.PeerPort = 0 }, goterrors.ErrInvalidArgs},
		{"source-unspecified", func(i *ip6.MessageInfo) { i.SockAddr = ip6.Address{} }, goterrors.ErrInvalidArgs},
		{"peer-unspecified", func(i *ip6.MessageInfo) { i.PeerAddr = ip6.Address{} }, goterrors.ErrInvalidArgs},
		{"source-loopback", func(i *ip6.MessageInfo) { i.SockAddr = ip6.Address{15: 1} }, goterrors.ErrInvalidArgs},
		{"peer-loopback", func(i *ip6.MessageInfo) { i.PeerAddr = ip6.Address{15: 1} }, goterrors.ErrInvalidArgs},
		{"source-multicast", func(i *ip6.MessageInfo) { i.SockAddr = ip6.Address{0xff, 2, 15: 1} }, goterrors.ErrInvalidArgs},
		{"peer-multicast", func(i *ip6.MessageInfo) { i.PeerAddr = ip6.Address{0xff, 2, 15: 1} }, goterrors.ErrNotCapable},
		{"unassigned", func(i *ip6.MessageInfo) { i.SockAddr[15] ^= 1 }, goterrors.ErrInvalidSourceAddress},
		{"unknown-neighbor", func(i *ip6.MessageInfo) { i.PeerAddr[15] ^= 1 }, goterrors.ErrNoRoute},
		{"off-mesh", func(i *ip6.MessageInfo) { i.PeerAddr = ip6.Address{0x20, 1, 0xdb, 8, 15: 2} }, goterrors.ErrNoRoute},
		{"local-loop", func(i *ip6.MessageInfo) { i.PeerAddr = i.SockAddr }, goterrors.ErrNoRoute},
		{"scope-mismatch", func(i *ip6.MessageInfo) { i.PeerAddr = inst.GetMeshLocalAddress() }, goterrors.ErrNoRoute},
		{"ecn", func(i *ip6.MessageInfo) { i.Ecn = ip6.EcnMarked }, goterrors.ErrNotCapable},
		{"ecn-invalid", func(i *ip6.MessageInfo) { i.Ecn = 99 }, goterrors.ErrNotCapable},
		{"multicast-loop", func(i *ip6.MessageInfo) { i.MulticastLoop = true }, goterrors.ErrNotCapable},
		{"host-interface", func(i *ip6.MessageInfo) { i.IsHostInterface = true }, goterrors.ErrNotCapable},
		{"literal-zero-hop", func(i *ip6.MessageInfo) { i.AllowZeroHopLimit = true }, goterrors.ErrNotCapable},
		{"link-info", func(i *ip6.MessageInfo) { i.LinkInfo = &ip6.LinkInfo{} }, goterrors.ErrNotCapable},
	}
	if err := inst.Do(context.Background(), func() error {
		before := inst.keyManager.GetMacFrameCounter()
		for _, test := range tests {
			info := valid
			test.edit(&info)
			if got := inst.SendUDP(nil, info); got != test.want {
				t.Errorf("%s: admission=%v, want identical %v", test.name, got, test.want)
			}
		}
		if got := inst.SendUDP(make([]byte, 65536), valid); got != goterrors.ErrNoBufs {
			t.Errorf("oversize uint16 truncation admission=%v", got)
		}
		if len(inst.forwarder.GetDirectQueue()) != 0 || inst.keyManager.GetMacFrameCounter() != before {
			t.Error("rejected datagram changed queue or security counters")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSendUDPStateAndForwarderErrors(t *testing.T) {
	inst, _, info := newReadyUDPInstance(t, nil)
	if err := inst.Do(context.Background(), func() error {
		saved := inst.forwarder
		inst.forwarder = nil
		if err := inst.SendUDP(nil, info); err != goterrors.ErrInvalidState {
			t.Errorf("missing forwarder=%v", err)
		}
		if err := inst.sendUDP(nil, info.SockAddr, info.SockPort, info.PeerAddr, info.PeerPort); err != goterrors.ErrInvalidState {
			t.Errorf("private missing forwarder=%v", err)
		}
		inst.forwarder = saved
		saved.SetEnabled(false)
		if err := inst.SendUDP(nil, info); err != mesh.ErrForwarderDisabled {
			t.Errorf("disabled forwarder=%v", err)
		}
		saved.SetEnabled(true)
		inst.ifConfigUp = false
		if err := inst.SendUDP(nil, info); err != goterrors.ErrInvalidState {
			t.Errorf("down interface=%v", err)
		}
		inst.ifConfigUp = true
		inst.threadEnabled = false
		if err := inst.SendUDP(nil, info); err != goterrors.ErrInvalidState {
			t.Errorf("disabled Thread=%v", err)
		}
		inst.threadEnabled = true
		if err := inst.mleService.Mle().BecomeDetached(); err != nil {
			return err
		}
		if err := inst.SendUDP(nil, info); err != goterrors.ErrDetached {
			t.Errorf("detached Thread=%v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	inst.Stop()
	if err := inst.SendUDP(nil, info); err != goterrors.ErrInvalidState {
		t.Errorf("stopped instance=%v", err)
	}
}

func TestSendUDPRejectsUnsupportedNeighborsAndDestinations(t *testing.T) {
	inst, _, info := newReadyUDPInstance(t, nil)
	if err := inst.Do(context.Background(), func() error {
		neighbor := inst.routerTable.FindRouterByID(2)
		neighbor.Mode.Set(0)
		if err := inst.SendUDP(nil, info); err != goterrors.ErrNoRoute {
			t.Errorf("sleepy neighbor admission=%v", err)
		}
		neighbor.Mode.Set(0x0f)
		neighbor.State = routing.StateRestored
		if err := inst.SendUDP(nil, info); err != goterrors.ErrNoRoute {
			t.Errorf("restored-but-not-valid neighbor admission=%v", err)
		}
		neighbor.State = routing.StateValid
		meshInfo := info
		meshInfo.SockAddr = inst.GetMeshLocalAddress()
		meshInfo.PeerAddr = meshInfo.SockAddr
		for _, rloc := range []uint16{0x0c00, 0x0801, 0xfc00, 0xffff} {
			iid := meshInfo.PeerAddr.GetIid()
			iid.SetLocator(rloc)
			copy(meshInfo.PeerAddr[8:], iid[:])
			if err := inst.SendUDP(nil, meshInfo); err != goterrors.ErrNoRoute {
				t.Errorf("unknown/multi-hop/anycast RLOC %04x admission=%v", rloc, err)
			}
		}
		meshInfo.PeerAddr = inst.GetMeshLocalAddress()
		meshInfo.PeerAddr[15] = 23 // Non-locator mesh-local EID.
		if err := inst.SendUDP(nil, meshInfo); err != goterrors.ErrNoRoute {
			t.Errorf("unresolved EID admission=%v", err)
		}
		inst.keyManager = key.NewManager()
		if err := inst.SendUDP(nil, info); err != goterrors.ErrSecurity {
			t.Errorf("missing security material=%v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSendUDPAssignedSourceAndParentRoute(t *testing.T) {
	inst, r, info := newReadyUDPInstance(t, nil)
	var macKey [16]byte
	if err := inst.Do(context.Background(), func() error {
		macKey = inst.keyManager.GetCurrentMacKey()
		inst.routerTable.FindRouterByID(2).State = routing.StateInvalid
		m := inst.mleService.Mle()
		parent := m.GetParent()
		parent.MacAddr = udpPeerExt
		parent.RLOC16 = 0x0800
		parent.State = mle.StateValid
		parent.Mode.Set(0x0f)
		if err := m.SetStateChild(0x0801); err != nil {
			return err
		}
		inst.SetRLOC16(0x0801)
		local := ip6.UnicastAddress{
			Address: ip6.Address{0xfd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 8: 0x12, 15: 0x34},
		}
		inst.netif.AddUnicastAddress(&local)
		info.SockAddr = local.Address
		info.PeerAddr = inst.GetMeshLocalAddress()
		iid := info.PeerAddr.GetIid()
		iid.SetLocator(parent.RLOC16)
		copy(info.PeerAddr[8:], iid[:])
		if err := inst.SendUDP(nil, info); err != goterrors.ErrInvalidSourceAddress {
			t.Errorf("invalid assigned source=%v", err)
		}
		inst.netif.RemoveUnicastAddress(&local)
		local.Valid = true
		inst.netif.AddUnicastAddress(&local)
		mapped := ip6.UnicastAddress{Address: ip6.Address{10: 0xff, 11: 0xff, 12: 127, 15: 1}, Valid: true}
		inst.netif.AddUnicastAddress(&mapped)
		badInfo := info
		badInfo.SockAddr = mapped.Address
		if err := inst.SendUDP(nil, badInfo); err != goterrors.ErrInvalidSourceAddress {
			t.Errorf("IPv4-mapped source=%v", err)
		}
		return inst.SendUDP([]byte{7}, info)
	}); err != nil {
		t.Fatal(err)
	}
	frame := captureUDP(t, r)
	gotInfo, data, _ := decodeUDP(t, &frame.frame, macKey)
	if gotInfo.SockAddr != info.SockAddr || gotInfo.PeerAddr != info.PeerAddr || !bytes.Equal(data, []byte{7}) {
		t.Fatalf("assigned source/parent route mismatch: %+v %x", gotInfo, data)
	}
}

func TestSendUDPForwardQueueCapacity(t *testing.T) {
	inst, _, info := newReadyUDPInstance(t, nil)
	if err := inst.Do(context.Background(), func() error {
		for range mesh.MaxFramesInDirectTxQueue {
			if err := inst.SendUDP([]byte{1}, info); err != nil {
				return err
			}
		}
		if err := inst.SendUDP(nil, info); err != mesh.ErrQueueFull {
			t.Errorf("full real forwarding queue=%v, want identical ErrQueueFull", err)
		}
		if len(inst.forwarder.GetDirectQueue()) != mesh.MaxFramesInDirectTxQueue {
			t.Error("forwarding admission exceeded real queue bound")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type udpFaultSettings struct {
	*simulation.SimSettings
	fail error
}

func (s *udpFaultSettings) Set(k platform.SettingsKey, data []byte) error {
	if k == platform.SettingsKeyNetworkInfo && s.fail != nil {
		return s.fail
	}
	return s.SimSettings.Set(k, data)
}

func TestSendUDPPersistenceFailureBeforeAndAfterAdmission(t *testing.T) {
	for _, afterAdmission := range []bool{false, true} {
		t.Run(map[bool]string{true: "after-admission", false: "before-admission"}[afterAdmission], func(t *testing.T) {
			s := &udpFaultSettings{SimSettings: simulation.NewSimSettings()}
			inst, r, info := newReadyUDPInstance(t, s)
			writeErr := errors.New("counter persistence failed")
			if err := inst.Do(context.Background(), func() error {
				if afterAdmission {
					if err := inst.SendUDP([]byte{1}, info); err != nil {
						return err
					}
				}
				s.fail = writeErr
				if !afterAdmission {
					inst.SetCurrentKeySequence(2, key.ForceUpdate)
					if err := inst.SendUDP([]byte{1}, info); !errors.Is(err, writeErr) {
						t.Errorf("latched persistence admission=%v", err)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := inst.Do(context.Background(), func() error {
				if !errors.Is(inst.PersistenceError(), writeErr) {
					t.Error("queued counter failure was not observable")
				}
				if err := inst.SendUDP(nil, info); !errors.Is(err, writeErr) {
					t.Errorf("send after persistence failure=%v", err)
				}
				if afterAdmission && inst.forwarder.GetCounters().TxDropped != 1 {
					t.Error("queued reservation failure was not reported as dropped")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-r.captures:
				t.Fatal("frame transmitted despite persistence failure")
			default:
			}
		})
	}
}

func TestSendUDPAcceptanceIsNotRadioCompletion(t *testing.T) {
	inst, r, info := newReadyUDPInstance(t, nil)
	if err := inst.Do(context.Background(), func() error {
		r.txErr = goterrors.ErrBusy
		return inst.SendUDP([]byte{1}, info)
	}); err != nil {
		t.Fatalf("queue acceptance waited for radio result: %v", err)
	}
	waitUDPCondition(t, inst, func() bool { return inst.forwarder.GetCounters().TxDropped == 1 })
	if err := inst.Do(context.Background(), func() error {
		total, success, _, _, _, failedCCA := inst.mac.GetCounters()
		if total != 1 || success != 0 || failedCCA != 1 {
			t.Errorf("radio failure counters = total:%d success:%d failedCCA:%d", total, success, failedCCA)
		}
		r.txErr = nil
		return inst.SendUDP([]byte{2}, info)
	}); err != nil {
		t.Fatal(err)
	}
	_ = captureUDP(t, r)
}

func waitUDPCondition(t *testing.T, inst *Instance, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var ready bool
		if err := inst.Do(context.Background(), func() error { ready = condition(); return nil }); err != nil {
			t.Fatal(err)
		}
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("asynchronous UDP observation did not become ready")
		}
		runtime.Gosched()
	}
}

func TestUDPRealRXBoundedBorrowedCopiesAndClose(t *testing.T) {
	inst, _, info := newReadyUDPInstance(t, nil)
	type receivedDatagram struct {
		payload []byte
		info    ip6.MessageInfo
	}
	incoming := make(chan receivedDatagram, 2)
	socket := &udp.Socket{}
	dropped, callbacks := 0, 0
	var capturedKey [16]byte
	if err := inst.Do(context.Background(), func() error {
		capturedKey = inst.keyManager.GetCurrentMacKey()
		if err := inst.udpManager.Open(socket, udp.NetifThreadInternal, func(payload []byte, metadata *ip6.MessageInfo) {
			callbacks++
			copyInfo := *metadata
			if metadata.LinkInfo != nil {
				link := *metadata.LinkInfo
				copyInfo.LinkInfo = &link
			}
			snapshot := receivedDatagram{payload: append([]byte(nil), payload...), info: copyInfo}
			select {
			case incoming <- snapshot:
			default:
				dropped++
			}
		}); err != nil {
			return err
		}
		return inst.udpManager.Bind(socket, ip6.SockAddr{Address: info.SockAddr, Port: info.SockPort})
	}); err != nil {
		t.Fatal(err)
	}
	var srcExt types.ExtAddress
	if err := inst.Do(context.Background(), func() error { srcExt = inst.GetExtAddress(); return nil }); err != nil {
		t.Fatal(err)
	}
	meta := mesh.BuildUDPMetadata(info.PeerAddr, info.SockAddr, info.PeerPort, info.SockPort, 42)
	meta.SrcExtAddr, meta.DstExtAddr = udpPeerExt, srcExt
	meta.SecurityEnabled = true
	meta.Security = mesh.SecurityMaterial{Key: capturedKey, KeyIdMode: 1}
	message := mesh.NewTxMessageWithMetadata([]byte{4, 5, 6}, 0x0400, 0x0800, meta)
	wire, err := mesh.BuildTxFrame(message, 1)
	if err != nil {
		t.Fatal(err)
	}
	frame := &radio.Frame{PSDU: wire, Channel: 20, RxInfo: &radio.RxInfo{RSSI: -37}}
	if err := inst.Do(context.Background(), func() error {
		for range 3 {
			inst.subMac.HandleReceiveDone(frame, nil)
		}
		// Close while two copied callbacks remain queued in application space.
		if err := inst.udpManager.Close(socket); err != nil {
			return err
		}
		inst.subMac.HandleReceiveDone(frame, nil)
		if callbacks != 3 || dropped != 1 {
			t.Errorf("bounded receive: callbacks=%d dropped=%d", callbacks, dropped)
		}
		for i := range frame.PSDU {
			frame.PSDU[i] = 0xff
		}
		frame.RxInfo.RSSI = -90
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		snapshot := <-incoming
		if !bytes.Equal(snapshot.payload, []byte{4, 5, 6}) || snapshot.info.SockAddr != info.SockAddr ||
			snapshot.info.PeerAddr != info.PeerAddr || snapshot.info.HopLimit != 42 ||
			snapshot.info.LinkInfo == nil || snapshot.info.LinkInfo.RSSI != -37 {
			t.Fatalf("borrowed receive data was not preserved: %+v %x", snapshot.info, snapshot.payload)
		}
	}
}
