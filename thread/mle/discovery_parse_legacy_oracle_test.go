package mle

import (
	"testing"

	"github.com/hilli/gothread/meshcop"
)

// Same existing parser/encoder APIs are present in accepted5aee.
func discoveryBoundedParseInput(name string, steering []byte) []TLV {
	response := encodeDiscoveryResponse(DiscoveryResponseData{Version: ThreadVersion})
	data := appendMeshCoPSubTLV(nil, meshcop.TLVDiscoveryResponse, response[:])
	data = appendMeshCoPSubTLV(data, meshcop.TLVExtendedPanID, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	data = appendMeshCoPSubTLV(data, meshcop.TLVNetworkName, []byte(name))
	if steering != nil {
		data = appendMeshCoPSubTLV(data, meshcop.TLVSteeringData, steering)
	}
	return []TLV{{Type: TLVDiscovery, Value: data}}
}

func TestExistingDiscoveryParserOwnsSteeringAndRejectsOversize(t *testing.T) {
	input := discoveryBoundedParseInput("network", []byte{1, 2})
	first, err := ParseDiscoveryResponse(input)
	if err != nil {
		t.Fatal(err)
	}
	first.SteeringData[0] = 9
	again, err := ParseDiscoveryResponse(input)
	if err != nil || again.SteeringData[0] != 1 {
		t.Fatal("parsed discovery steering aliases actual wire storage")
	}
	if _, err := ParseDiscoveryResponse(discoveryBoundedParseInput("0123456789abcdefX", nil)); err == nil {
		t.Fatal("oversized actual NetworkName accepted")
	}
	if _, err := ParseDiscoveryResponse(discoveryBoundedParseInput("network", make([]byte, 17))); err == nil {
		t.Fatal("oversized actual SteeringData accepted or silently truncated")
	}
}
