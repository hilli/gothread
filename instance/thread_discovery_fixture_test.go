package instance

import (
	"testing"
	"time"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/discover"
	"github.com/hilli/gothread/thread/lowpan"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

// Candidate-only actual native composition, not RF/interoperability proof.
type discoveryProbeRadio struct {
	*fragmentRadio
	channel              uint8
	pan                  uint16
	state                radio.State
	failChannel          uint8
	receiveErr, sleepErr error
	sleepStateMismatch   bool
}

func (driver *discoveryProbeRadio) Receive(channel uint8) error {
	if driver.receiveErr != nil && driver.failChannel == channel {
		return driver.receiveErr
	}
	driver.channel, driver.state = channel, radio.StateReceive
	return nil
}
func (driver *discoveryProbeRadio) Sleep() error {
	if driver.sleepErr != nil {
		return driver.sleepErr
	}
	if driver.sleepStateMismatch {
		return nil
	}
	driver.state = radio.StateSleep
	return nil
}
func (driver *discoveryProbeRadio) SetPanID(pan uint16)   { driver.pan = pan }
func (driver *discoveryProbeRadio) GetState() radio.State { return driver.state }

func discoverySourceFixture(t *testing.T, attached bool) (*ownedAttachFixture, *discoveryProbeRadio) {
	t.Helper()
	var probe *discoveryProbeRadio
	fixture := newOwnedAttachFixtureWithRadio(t, true, nil, func(base *fragmentRadio) radio.Radio {
		probe = &discoveryProbeRadio{fragmentRadio: base}
		return probe
	})
	// Optional capture-helper NV snapshots are not a credential requirement
	// for a plain discovery packet. Instance Settings remain unchanged.
	fixture.node.driver.settings = nil
	if attached {
		fixture, _, _ = publicFTDWireFixtureFor(t, fixture, ownedPrefixWire(true))
	} else {
		mustSRPLoop(t, fixture.node.inst, func() error {
			fixture.node.inst.mac.SetPanID(0xface)
			fixture.node.inst.mac.SetPanChannel(20)
			return nil
		})
	}
	return fixture, probe
}

func beginSourceDiscovery(t *testing.T, fixture *ownedAttachFixture, mask uint32) *ThreadDiscoveryAttempt {
	return beginSourceDiscoveryTimeout(t, fixture, mask, time.Second)
}
func beginSourceDiscoveryTimeout(t *testing.T, fixture *ownedAttachFixture, mask uint32, timeout time.Duration) *ThreadDiscoveryAttempt {
	t.Helper()
	var attempt *ThreadDiscoveryAttempt
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		attempt, err = fixture.node.inst.BeginThreadDiscovery(ThreadDiscoveryConfig{
			ChannelMask: mask, ChannelDuration: 10 * time.Millisecond, Timeout: timeout,
		})
		return err
	})
	return attempt
}

func assertActualDiscoveryRequest(t *testing.T, fixture *ownedAttachFixture, channel uint8) udpRadioCapture {
	t.Helper()
	capture := captureUDP(t, fixture.node.driver.boundedUDPRadio)
	context, offset, err := mesh.NewFramer().ParseFrameHeader(capture.frame.PSDU)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := lowpan.DecompressDatagram(capture.frame.PSDU[offset:], lowpan.AddressContext{
		SrcExtAddr: context.SrcExtAddr, DstExtAddr: context.DstExtAddr,
		DstShort: types.ShortAddress(context.DstShortAddr), DstShortValid: context.UseDstShort,
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := mle.ParseMessage(packet[48:])
	if err != nil || wire.SecuritySuite != mle.SecuritySuiteNone || len(wire.Payload) == 0 ||
		mle.Command(wire.Payload[0]) != mle.CommandDiscoveryRequest || context.SecurityEnabled ||
		context.PanId != 0xffff || !context.UseDstShort || context.DstShortAddr != 0xffff ||
		capture.frame.Channel != channel || capture.frame.TxInfo == nil || capture.frame.TxInfo.SubmissionID == 0 ||
		packet[7] != mle.ControlHopLimit || !validNativeUDP(packet) {
		t.Fatal("no actual checked plain DiscoveryRequest/channel/PAN/UDP/submission")
	}
	var destination ip6.Address
	copy(destination[:], packet[24:40])
	if destination != mle.LinkLocalAllNodesMulticast {
		t.Fatal("private discovery TX escaped its destination")
	}
	completeNativeFrame(t, fixture.node, capture, nil)
	mustSRPLoop(t, fixture.node.inst, func() error { return nil })
	return capture
}

func awaitDiscoveryOutcome(t *testing.T, attempt *ThreadDiscoveryAttempt) discover.ScanOutcome {
	t.Helper()
	select {
	case outcome, open := <-attempt.Result():
		if !open {
			t.Fatal("missing discovery terminal outcome")
		}
		return outcome
	case <-time.After(3 * time.Second):
		t.Fatal("discovery terminal outcome did not arrive")
		return discover.ScanOutcome{}
	}
}

type discoveryPeerTransport struct {
	inst        *Instance
	identity    types.ExtAddress
	payload     []byte
	destination ip6.Address
}

func (transport *discoveryPeerTransport) SendMLE(payload []byte, destination ip6.Address) error {
	transport.payload, transport.destination = append([]byte(nil), payload...), destination
	return nil
}
func (transport *discoveryPeerTransport) GetExtAddress() types.ExtAddress { return transport.identity }
func (transport *discoveryPeerTransport) GetLinkLocalAddress() ip6.Address {
	return linkLocalAddress(transport.identity)
}
func (transport *discoveryPeerTransport) GetMeshLocalAddress() ip6.Address {
	return transport.inst.GetMeshLocalAddress()
}
func (*discoveryPeerTransport) GetLinkLocalAllRoutersMulticast() ip6.Address {
	return ip6.MulticastLinkLocalAllRouters
}

type discoveryPeerInfo struct{}

func (discoveryPeerInfo) GetNetworkName() string     { return "actual-scan" }
func (discoveryPeerInfo) GetExtendedPanID() [8]byte  { return [8]byte{1, 2, 3, 4, 5, 6, 7, 8} }
func (discoveryPeerInfo) GetSteeringData() []byte    { return []byte{0xff} }
func (discoveryPeerInfo) IsNativeCommissioner() bool { return false }

// The model peer uses the real DiscoveryHandler encoder and MAC/6LoWPAN
// builder; its RX injection is never counted as the local outbound request.
func discoveryPeerFrame(t *testing.T, fixture *ownedAttachFixture, channel uint8, pan uint16) radio.Frame {
	return discoveryPeerFrameFrom(t, fixture, channel, pan, udpPeerExt)
}
func discoveryPeerFrameFrom(t *testing.T, fixture *ownedAttachFixture, channel uint8, pan uint16, identity types.ExtAddress) radio.Frame {
	t.Helper()
	inst := fixture.node.inst
	transport := &discoveryPeerTransport{inst: inst, identity: identity}
	handler := mle.NewDiscoveryHandler(mle.NewMle(), mle.NewDispatcher(mle.NewMle(), inst.keyManager, transport), discoveryPeerInfo{})
	if err := handler.SendDiscoveryResponse(inst.GetLinkLocalAddress()); err != nil {
		t.Fatal(err)
	}
	metadata := mesh.BuildUDPMetadata(linkLocalAddress(identity), transport.destination, mle.UDPPort, mle.UDPPort, mle.ControlHopLimit)
	metadata.SrcExtAddr, metadata.DstExtAddr = identity, fragmentSource
	metadata.PanId = pan
	message := mesh.NewTxMessageWithMetadata(transport.payload, 0x0801, 0x0800, metadata)
	packet, err := mesh.BuildTxFrame(message, 17)
	if err != nil {
		t.Fatal(err)
	}
	return radio.Frame{PSDU: packet, Channel: channel, RxInfo: &radio.RxInfo{RSSI: -41, LQI: 99}}
}
