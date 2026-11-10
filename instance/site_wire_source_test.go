package instance

import (
	"bytes"
	"errors"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

func TestSiteTunnelActualLiteral96ByteWrapperAnd1184Limit(t *testing.T) {
	prefix := [8]byte{0xfd, 1, 2, 3, 4, 5, 6, 7}
	source := ip6.Address{0xfd, 1, 2, 3, 4, 5, 6, 7, 8: 0x61, 15: 0x29}
	destination := ip6.Address{0xff, 0x35, 0, 0x40, 0xfd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0, 0x12, 0x34}
	outer := meshLocator(prefix, 0x0801)
	data := bytes.Repeat([]byte{0x5a}, 1184)
	packet, err := encodeSiteTunnel(data, ip6.MessageInfo{SockAddr: source, PeerAddr: destination, SockPort: 5540, PeerPort: 5540, HopLimit: 64},
		outer, 0x0801, 0x73)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != 1280 || len(packet)-len(data) != 96 {
		t.Fatal("actual encoder violated exact IPv6 MTU/wrapper")
	}
	if !bytes.Equal(packet[40:48], []byte{41, 0, 0x6d, 4, 0x40, 0x73, 8, 1}) {
		t.Fatal("not literal eight-byte MPL HBH")
	}
	if packet[54] != 17 || packet[55] != 64 || !bytes.Equal(packet[56:72], source[:]) ||
		!bytes.Equal(packet[72:88], destination[:]) {
		t.Fatal("inner IPv6 tuple/hop not preserved")
	}
	inner, seed, sequence, err := decodeSiteTunnel(packet, prefix)
	if err != nil || seed != 0x0801 || sequence != 0x73 || !bytes.Equal(inner[48:], data) || !validNativeUDP(inner) {
		t.Fatal("actual tunnel decoder/checksum/seed did not retain original datagram")
	}
	info := ip6.MessageInfo{SockAddr: source, PeerAddr: destination, SockPort: 5540, PeerPort: 5540}
	if packet, err := encodeSiteTunnel(make([]byte, 1185), info, outer, 0x0801, 0); packet != nil || !errors.Is(err, goterrors.ErrNoBufs) {
		t.Fatal("1185 reached encoder allocation/admission")
	}
	var noOwner *MulticastMembership
	if err := noOwner.SendUDP(make([]byte, 1185), info); !errors.Is(err, goterrors.ErrNoBufs) {
		t.Fatal("public1185 threshold was not checked before owner/resource access")
	}
}

func TestSiteTunnelRejectsOtherPortsGeometryAndInnerChecksum(t *testing.T) {
	prefix := [8]byte{0xfd, 1, 2, 3, 4, 5, 6, 7}
	info := ip6.MessageInfo{
		SockAddr: ip6.Address{0xfd, 1, 2, 3, 4, 5, 6, 7, 15: 0x61},
		PeerAddr: ip6.Address{0xff, 0x35, 0, 0x40, 4: 0xfd, 15: 1}, SockPort: 5540, PeerPort: 5540,
	}
	packet, err := encodeSiteTunnel([]byte("immutable"), info, meshLocator(prefix, 0x0801), 0x0801, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{6, 24, 40, 41, 42, 43, 44, 47, 90, len(packet) - 1} {
		bad := append([]byte(nil), packet...)
		bad[offset] ^= 1
		if _, _, _, err := decodeSiteTunnel(bad, prefix); err == nil {
			t.Fatalf("invalid byte%d accepted", offset)
		}
	}
}
