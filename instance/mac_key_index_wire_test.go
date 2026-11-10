package instance

import (
	"context"
	"fmt"
	"testing"

	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/mesh"
)

func TestNativeMode1RejectsIllegalZeroIndexWithValidMIC(t *testing.T) {
	source := newFragmentEndpoint(t, fragmentSource, udpPeerExt, 0x0400, 0x0800, simulation.NewSimSettings())
	destination := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
	info := fragmentInfo(fragmentSource, udpPeerExt, false)
	if err := source.inst.Do(context.Background(), func() error { return source.inst.SendUDP([]byte("index"), info) }); err != nil {
		t.Fatal(err)
	}
	capture := captureUDP(t, source.driver.boundedUDPRadio)
	header, adaptation := nativeAdaptation(t, capture, source.macKey)
	completeNativeFrame(t, source, capture, nil)
	header.Security.KeyId = 0
	header.Security.Key = source.macKey
	illegal, err := mesh.NewFramer().BuildDataFrame(header, adaptation)
	if err != nil {
		t.Fatal(err)
	}
	bad := capture
	bad.frame.PSDU = illegal // Independent wire index0, with correctly recomputed current-key MIC.
	deliverNativeFrame(t, destination, bad)
	mustSRPLoop(t, destination.inst, func() error {
		if len(destination.incoming) != 0 {
			return fmt.Errorf("illegal Thread Mode1 index0 accepted despite valid MIC")
		}
		return nil
	})
	if err := source.inst.Do(context.Background(), func() error { return source.inst.SendUDP([]byte("index"), info) }); err != nil {
		t.Fatal(err)
	}
	valid := captureUDP(t, source.driver.boundedUDPRadio)
	frameContext, _, err := mesh.NewFramer().ParseFrameHeader(valid.frame.PSDU)
	if err != nil || frameContext.Security.KeyId != 1 {
		t.Fatal("actual sequence0 producer did not emit literal standard index1")
	}
	deliverNativeFrame(t, destination, valid)
	completeNativeFrame(t, source, valid, nil)
	select {
	case packet := <-destination.incoming:
		if string(packet.payload) != "index" {
			t.Fatal("valid-index payload corrupted")
		}
	default:
		t.Fatal("standard index1 not delivered")
	}
}
