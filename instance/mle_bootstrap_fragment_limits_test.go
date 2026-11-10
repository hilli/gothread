package instance

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/thread/lowpan"
	"github.com/hilli/gothread/thread/mesh"
)

func TestOwnedCIDQuarantineLiteralGeometryAndWrongPort(t *testing.T) {
	fixture, parent := ownedCIDPending(t)
	captures := captureParentAttachMessage(t, parent, fixture, childIDResponseWithNetworkData(0x0801, largeBootstrapNetworkData()), 61, nil)
	context, offset, err := mesh.NewFramer().ParseFrameHeader(captures[0].frame.PSDU)
	if err != nil {
		t.Fatal(err)
	}
	wire := captures[0].frame.PSDU[offset:]
	header, n, err := lowpan.ParseFragmentHeader(wire)
	if err != nil || !header.IsFirst {
		t.Fatal("not real FRAG1")
	}
	first, err := lowpan.DecompressDatagram(wire[n:], lowpan.AddressContext{
		SrcExtAddr: context.SrcExtAddr, DstExtAddr: context.DstExtAddr,
	}, header.DatagramSize)
	if err != nil {
		t.Fatal(err)
	}
	key := mesh.FragmentKey{Scope: mesh.FragmentScope{
		Source: [8]byte(udpPeerExt), Destination: [8]byte(fragmentSource), PanID: 0xface, Channel: 20,
	}, Tag: header.DatagramTag, Size: header.DatagramSize}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if !fixture.node.inst.initialMLEEnvelope(first, key.Size, key) {
			return fmt.Errorf("actual owned FRAG1 prefix rejected")
		}
		for _, size := range []uint16{0, 62, 63, 1281} {
			if fixture.node.inst.initialMLEEnvelope(first, size, key) {
				return fmt.Errorf("invalid size%d accepted", size)
			}
		}
		maximum := append([]byte(nil), first...)
		binary.BigEndian.PutUint16(maximum[4:6], 1240)
		binary.BigEndian.PutUint16(maximum[44:46], 1240)
		if !fixture.node.inst.initialMLEEnvelope(maximum, 1280, key) {
			return fmt.Errorf("exact outer geometry limit rejected")
		}
		wrong := append([]byte(nil), first...)
		binary.BigEndian.PutUint16(wrong[42:44], 5540)
		if fixture.node.inst.initialMLEEnvelope(wrong, key.Size, key) {
			return fmt.Errorf("ordinary UDP/Matter admitted to MLE quarantine")
		}
		wrong = append([]byte(nil), first...)
		wrong[7] = 64
		if fixture.node.inst.initialMLEEnvelope(wrong, key.Size, key) {
			return fmt.Errorf("application hop limit admitted as MLE")
		}
		wrongKey := key
		wrongKey.Scope.Source = [8]byte(types.ExtAddress{0x22, 9})
		if fixture.node.inst.initialMLEEnvelope(first, key.Size, wrongKey) {
			return fmt.Errorf("source tuple unbound")
		}
		return nil
	})
}

func TestOwnedCIDQuarantineExpiryCannotPublishChild(t *testing.T) {
	fixture, parent := ownedCIDPending(t)
	captures := captureParentAttachMessage(t, parent, fixture, childIDResponseWithNetworkData(0x0801, largeBootstrapNetworkData()), 61, nil)
	deliverAttachCaptures(t, fixture, captures[:1])
	mustSRPLoop(t, fixture.node.inst, func() error {
		fixture.now = fixture.now.Add(time.Minute)
		fixture.node.inst.timers.processExpired()
		return nil
	})
	if result := awaitOwnedAttach(t, fixture.attempt); result.Err == nil {
		t.Fatal("expired CID exchange completed successfully")
	}
	deliverAttachCaptures(t, fixture, captures[1:])
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.initialMLEFragment != nil || fixture.node.inst.mleService.Mle().IsChild() {
			return fmt.Errorf("expired fragments revived candidate/role")
		}
		return nil
	})
}
