package srp

import (
	"bytes"
	stdsha256 "crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/hilli/gothread/crypto/ecdsa"
	"github.com/hilli/gothread/net/dns"
)

type literalUpdateRR struct {
	name         string
	kind, class  uint16
	ttl          uint32
	start, rdata int
	data         []byte
}

func literalUpdateRecords(t *testing.T, data []byte) []literalUpdateRR {
	t.Helper()
	_, end, err := dns.ReadName(data, 12)
	if err != nil {
		t.Fatal(err)
	}
	offset := end + 4
	var records []literalUpdateRR
	for range binary.BigEndian.Uint16(data[8:]) {
		start := offset
		name, header, err := dns.ReadName(data, offset)
		if err != nil || header+10 > len(data) {
			t.Fatal("RR owner/header invalid")
		}
		length := int(binary.BigEndian.Uint16(data[header+8:]))
		offset = header + 10 + length
		if offset > len(data) {
			t.Fatal("RR RDLENGTH invalid")
		}
		records = append(records, literalUpdateRR{name: name, kind: binary.BigEndian.Uint16(data[header:]),
			class: binary.BigEndian.Uint16(data[header+2:]), ttl: binary.BigEndian.Uint32(data[header+4:]),
			start: start, rdata: header + 10, data: data[header+10 : offset]})
	}
	if data[offset] != 0 || binary.BigEndian.Uint16(data[offset+1:]) != 41 {
		t.Fatal("declared UPDATE count does not end at OPT")
	}
	return records
}

func TestProductionServiceLiteralAddRemoveAndSubtypeRecords(t *testing.T) {
	env, service, _ := responseRegressionEnv(t)
	service.SubTypeLabels = []string{"_one", "_two", "_three", "_four", "_five"}
	env.fireTimer()
	packet := env.sender.lastPacket().data
	records := literalUpdateRecords(t, packet)
	if len(records) != 12 || records[0].kind != 12 || records[0].class != 1 {
		t.Fatal("add/subtypes record counts/types wrong")
	}
	if !bytes.Equal(packet[38:51], []byte("\x05_test\x04_udp\xc0\x0c")) ||
		!bytes.Equal(records[0].data, []byte("\x10response-service\xc0\x26")) {
		t.Fatal("literal PTR owner/RDATA compression fixture mismatch")
	}
	for i := 1; i <= 5; i++ {
		if records[i].kind != 12 || !bytes.Equal(records[i].data, []byte{0xc0, 0x3d}) {
			t.Fatal("subtype PTR did not target actual instance RDATA offset61")
		}
	}
	if records[6].kind != 255 || records[6].class != 255 || records[6].ttl != 0 ||
		len(records[6].data) != 0 || records[7].kind != 33 || records[8].kind != 16 {
		t.Fatal("mandatory service delete-all before SRV/TXT adds missing")
	}
	env.client.HandleResponse(buildSimpleResponse(currentSRPMessageID(t, env), dns.RcodeSuccess))
	if err := env.client.RemoveService(service); err != nil {
		t.Fatal(err)
	}
	env.fireTimer()
	records = literalUpdateRecords(t, env.sender.lastPacket().data)
	if len(records) != 5 || records[0].kind != 12 || records[0].class != 254 || records[0].ttl != 0 ||
		records[1].kind != 255 || records[1].class != 255 || len(records[1].data) != 0 {
		t.Fatal("PTR-delete + service DeleteAll removal fixture mismatch")
	}
	for _, rr := range records {
		if rr.kind == 33 || rr.kind == 16 {
			t.Fatal("withdrawal re-added SRV/TXT")
		}
	}
}

func TestProductionHostWithdrawalActuallyRemoves(t *testing.T) {
	client, _, _ := responseRegressionEnv(t)
	server := newServerTestEnv(t)
	server.startServer()
	t.Cleanup(server.server.Stop)
	client.fireTimer()
	server.server.ProcessMessage(client.sender.lastPacket().data, defaultPeer())
	client.client.HandleResponse(server.responses[0].data)
	if err := client.client.RemoveHostAndServices(true, true); err != nil {
		t.Fatal(err)
	}
	client.fireTimer()
	server.server.ProcessMessage(client.sender.lastPacket().data, defaultPeer())
	var header dns.Header
	if err := header.UnmarshalBinary(server.responses[len(server.responses)-1].data); err != nil {
		t.Fatal(err)
	}
	if header.GetResponseCode() != dns.RcodeSuccess || len(server.server.GetHosts()) != 0 {
		t.Fatalf("real host withdrawal rejected/not removed: RCODE=%v retainedHosts=%d", header.GetResponseCode(), len(server.server.GetHosts()))
	}
}

func TestProductionCanonicalCaseAndInvalidSignature(t *testing.T) {
	client, _, _ := responseRegressionEnv(t)
	if err := client.client.SetHostName("ReSponse-Host"); err != nil {
		t.Fatal(err)
	}
	server := newServerTestEnv(t)
	server.startServer()
	t.Cleanup(server.server.Stop)
	client.fireTimer()
	packet := client.sender.lastPacket().data
	server.server.ProcessMessage(packet, defaultPeer())
	var header dns.Header
	if err := header.UnmarshalBinary(server.responses[0].data); err != nil || header.GetResponseCode() != dns.RcodeSuccess {
		t.Fatal("canonical case/compressed signer rejected")
	}
	invalid := append([]byte(nil), packet...)
	invalid[len(invalid)-1] ^= 0x80
	server.server.ProcessMessage(invalid, defaultPeer())
	if err := header.UnmarshalBinary(server.responses[1].data); err != nil || header.GetResponseCode() == dns.RcodeSuccess {
		t.Fatal("invalid actual signature accepted")
	}
}

func TestProductionSIG0IndependentCanonicalVector(t *testing.T) {
	client, _, _ := responseRegressionEnv(t)
	client.fireTimer()
	packet := client.sender.lastPacket().data
	_, zoneEnd, err := dns.ReadName(packet, dns.HeaderSize)
	if err != nil {
		t.Fatal(err)
	}
	offset := zoneEnd + 4
	count := int(binary.BigEndian.Uint16(packet[8:])) + 1 // UPDATEs + OPT
	for range count {
		_, header, err := dns.ReadName(packet, offset)
		if err != nil || header+10 > len(packet) {
			t.Fatal("invalid record layout before signature")
		}
		offset = header + 10 + int(binary.BigEndian.Uint16(packet[header+8:]))
	}
	sigRecord := offset
	if packet[sigRecord] != 0 || binary.BigEndian.Uint16(packet[sigRecord+1:]) != 24 {
		t.Fatal("missing literal root/SIG record")
	}
	rdata := sigRecord + 11
	_, signatureOffset, err := dns.ReadName(packet, rdata+18)
	if err != nil || signatureOffset+64 != len(packet) {
		t.Fatal("invalid SIG0 framing")
	}
	var signature ecdsa.Signature
	copy(signature[:], packet[signatureOffset:])
	// Independent RFC2931§3.1 / pinned OT canonical signer and pre-SIG count.
	canonical := []byte("\x0dresponse-host\x07default\x07service\x04arpa\x00")
	material := append([]byte(nil), packet[rdata:rdata+18]...)
	material = append(material, canonical...)
	header := append([]byte(nil), packet[:12]...)
	binary.BigEndian.PutUint16(header[10:], 1) // One OPT, excluding SIG(0).
	material = append(material, header...)
	material = append(material, packet[12:sigRecord]...)
	digest := stdsha256.Sum256(material)
	public := client.keyPair.GetPublicKey()
	if err := public.Verify(digest, signature); err != nil {
		// Isolate the source count defect, rather than blaming the server.
		material[len(canonical)+18+10] = 0
		material[len(canonical)+18+11] = 0
		oldDigest := stdsha256.Sum256(material)
		t.Fatalf("canonical ARCount1 signature invalid; ARCount0 verifies=%v, SIG offset=%d compressedSigner=%t",
			public.Verify(oldDigest, signature) == nil, sigRecord, packet[rdata+18]&0xc0 == 0xc0)
	}
	material[0] ^= 1
	invalid := stdsha256.Sum256(material)
	if public.Verify(invalid, signature) == nil {
		t.Fatal("invalid canonical material accepted")
	}
}

func TestClientFirstUpdateRecordHasRFC1035Layout(t *testing.T) {
	client, _, _ := responseRegressionEnv(t)
	client.fireTimer()
	packet := client.sender.lastPacket().data
	_, zoneEnd, err := dns.ReadName(packet, dns.HeaderSize)
	if err != nil {
		t.Fatal(err)
	}
	updateStart := zoneEnd + 4
	owner, rrStart, err := dns.ReadName(packet, updateStart)
	if err != nil {
		t.Fatal(err)
	}
	// Literal RFC1035 3.2.1: owner name is immediately followed by TYPE,
	// CLASS, TTL, RDLENGTH. No unattached compression-dictionary names.
	if owner != "_test._udp.default.service.arpa." ||
		binary.BigEndian.Uint16(packet[rrStart:]) != 12 ||
		binary.BigEndian.Uint16(packet[rrStart+2:]) != 1 {
		t.Fatalf("updateStart=%d owner=%q RRstart=%d actualType=%#04x actualClass=%#04x QD/AN/NS/AR=%d/%d/%d/%d; want PTR(000c)/IN(0001) immediately after owner",
			updateStart, owner, rrStart, binary.BigEndian.Uint16(packet[rrStart:]),
			binary.BigEndian.Uint16(packet[rrStart+2:]), binary.BigEndian.Uint16(packet[4:]),
			binary.BigEndian.Uint16(packet[6:]), binary.BigEndian.Uint16(packet[8:]),
			binary.BigEndian.Uint16(packet[10:]))
	}
}

func TestClientProductionUpdateAcceptedByRealServer(t *testing.T) {
	client, _, _ := responseRegressionEnv(t)
	server := newServerTestEnv(t)
	server.startServer()
	t.Cleanup(server.server.Stop)
	client.fireTimer()
	packet := client.sender.lastPacket().data
	peer := defaultPeer()
	meta := messageMetadata{offset: dns.HeaderSize, peer: &peer, rxTime: server.now,
		ttlConfig: server.server.ttlConfig, leaseConfig: server.server.leaseConfig}
	if err := meta.dnsHeader.UnmarshalBinary(packet); err != nil {
		t.Fatal(err)
	}
	if err := server.server.processZoneSection(packet, &meta); err != nil {
		t.Fatalf("production zone: %v", err)
	}
	host := &RegHost{}
	if err := server.server.processUpdateSection(packet, &meta, host); err != nil {
		t.Fatalf("production update: %v", err)
	}
	if err := server.server.processAdditionalSection(packet, &meta, host); err != nil {
		t.Fatalf("production additional: %v", err)
	}
	server.server.ProcessMessage(packet, defaultPeer())
	if len(server.responses) != 1 {
		t.Fatal("real server did not respond to production signed update")
	}
	var response dns.Header
	if err := response.UnmarshalBinary(server.responses[0].data); err != nil {
		t.Fatal(err)
	}
	if response.GetResponseCode() != dns.RcodeSuccess {
		t.Fatalf("production client/server wire rejected: RCODE=%v", response.GetResponseCode())
	}
	hosts := server.server.GetHosts()
	if len(hosts) != 1 || hosts[0].Lease != DefaultLease || len(hosts[0].Services) != 1 {
		t.Fatalf("registration ACK did not actually register requested default lease/service: hosts=%d", len(hosts))
	}
}
