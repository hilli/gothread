package instance

import (
	"testing"

	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

func TestInitialMLELiteralUnfragmentedBudgets(t *testing.T) {
	// Mandatory Parent Request: MLE suite/header/command/MIC16 plus
	// Mode3,Challenge10,ScanMask3,Version4 =36. Multicast IPHC3+UDPNHC7.
	if 16+3+10+3+4+3+7 != 46 {
		t.Fatal("request literal budget")
	}
	// Parent Response with full10-byte Connectivity and optional MLE counter:
	// MLE16+Source4+Version4+Response10+Leader10+Margin3+Connectivity12+
	// LinkCounter6+MLECounter6+Challenge10 =81. Link-local IPHC2+UDPNHC7.
	const response = 16 + 4 + 4 + 10 + 10 + 3 + 12 + 6 + 6 + 10
	message := parentResponse(make([]byte, 8))
	if len(message.Bytes())+mle.SecurityTagSize != response {
		t.Fatal("production response differs from mandatory/reference full-connectivity literal")
	}
	capacity := mesh.NewFramer().GetMaxPayloadSize(&mesh.FrameContext{
		UseSrcShort: false, UseDstShort: false, SecurityEnabled: false,
	})
	if response+2+7 > capacity {
		t.Fatal("reference initial Parent Response does not fit unfragmented MAC budget")
	}
	// This proves the selected compressed reference form, NOT arbitrary
	// optional extensions or uncompressed IPv6 from unknown peers.
}
