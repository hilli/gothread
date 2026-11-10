package srp

import (
	stdsha256 "crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/hilli/gothread/crypto/ecdsa"
	"github.com/hilli/gothread/net/dns"
)

func TestProductionCanonicalSignerPreservesLiteralDotLabel(t *testing.T) {
	client, _, _ := responseRegressionEnv(t)
	if err := client.client.SetHostName("NoDe.v2"); err != nil {
		t.Fatal(err)
	}
	client.fireTimer()
	packet := client.sender.lastPacket().data
	records := literalUpdateRecords(t, packet)
	last := records[len(records)-1]
	opt := last.rdata + len(last.data)
	sigRecord := opt + 11 + int(binary.BigEndian.Uint16(packet[opt+9:]))
	rdata := sigRecord + 11
	_, signatureOffset, err := dns.ReadName(packet, rdata+18)
	if err != nil {
		t.Fatal(err)
	}
	var signature ecdsa.Signature
	copy(signature[:], packet[signatureOffset:])
	// ONE length7 label containing a literal dot. NOT node/v2 labels.
	canonical := []byte("\x07node.v2\x07default\x07service\x04arpa\x00")
	material := append([]byte(nil), packet[rdata:rdata+18]...)
	material = append(material, canonical...)
	header := append([]byte(nil), packet[:12]...)
	binary.BigEndian.PutUint16(header[10:], 1)
	material = append(material, header...)
	material = append(material, packet[12:sigRecord]...)
	digest := stdsha256.Sum256(material)
	public := client.keyPair.GetPublicKey()
	if err := public.Verify(digest, signature); err != nil {
		t.Fatal("independent literal-label canonical signature invalid")
	}
	server := newServerTestEnv(t)
	server.startServer()
	t.Cleanup(server.server.Stop)
	server.server.ProcessMessage(packet, defaultPeer())
	var response dns.Header
	if err := response.UnmarshalBinary(server.responses[0].data); err != nil ||
		response.GetResponseCode() != dns.RcodeSuccess {
		t.Fatalf("strict server flattened valid single-label canonical signer: RCODE=%v", response.GetResponseCode())
	}
}
