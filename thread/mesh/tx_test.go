// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"testing"

	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/lowpan"
)

// TestNewTxMessageWithMetadata verifies that TxMessages with metadata
// are created correctly and that HasMetadata reports true.
func TestNewTxMessageWithMetadata(t *testing.T) {
	meta := BuildUDPMetadata(
		[16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		[16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		19788, 19788, 64,
	)
	msg := NewTxMessageWithMetadata([]byte{0xAA, 0xBB}, 0x0400, 0x0800, meta)

	if !msg.HasMetadata() {
		t.Fatal("HasMetadata() = false, want true")
	}
	if msg.Metadata.NextHeader != ip6.ProtoUDP {
		t.Errorf("NextHeader = %d, want %d", msg.Metadata.NextHeader, ip6.ProtoUDP)
	}
	if msg.Metadata.SrcPort != 19788 {
		t.Errorf("SrcPort = %d, want 19788", msg.Metadata.SrcPort)
	}
	if msg.MeshDest != 0x0400 {
		t.Errorf("MeshDest = 0x%04x, want 0x0400", msg.MeshDest)
	}

	// Legacy message without metadata.
	legacy := NewTxMessage([]byte{0x01}, 0x0400, 0x0800)
	if legacy.HasMetadata() {
		t.Fatal("legacy HasMetadata() = true, want false")
	}
}

// TestBuildTxFrame_UDP verifies that BuildTxFrame produces a valid
// 802.15.4 frame containing 6LoWPAN-compressed IPv6+UDP headers
// followed by the application payload.
func TestBuildTxFrame_UDP(t *testing.T) {
	srcAddr := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	dstAddr := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	srcExt := [8]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	dstExt := [8]byte{0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

	payload := []byte("hello")

	meta := &TxMetadata{
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		SrcPort:     19788,
		DstPort:     19788,
		NextHeader:  ip6.ProtoUDP,
		HopLimit:    64,
		SrcExtAddr:  srcExt,
		DstExtAddr:  dstExt,
		UseSrcShort: true,
		UseDstShort: true,
		PanId:       0x1234,
	}

	msg := NewTxMessageWithMetadata(payload, 0x0400, 0x0800, meta)
	frame, err := BuildTxFrame(msg, 42)
	if err != nil {
		t.Fatalf("BuildTxFrame() error: %v", err)
	}

	// The frame should be a valid 802.15.4 frame. Parse it to verify
	// basic structure.
	framer := NewFramer()
	ctx, headerLen, err := framer.ParseFrameHeader(frame)
	if err != nil {
		t.Fatalf("ParseFrameHeader() error: %v", err)
	}

	// Verify MAC header fields.
	if ctx.SequenceNumber != 42 {
		t.Errorf("SequenceNumber = %d, want 42", ctx.SequenceNumber)
	}
	if ctx.PanId != 0x1234 {
		t.Errorf("PanId = 0x%04x, want 0x1234", ctx.PanId)
	}
	if !ctx.UseSrcShort {
		t.Error("UseSrcShort = false, want true")
	}
	if !ctx.UseDstShort {
		t.Error("UseDstShort = false, want true")
	}
	if ctx.SrcShortAddr != 0x0800 {
		t.Errorf("SrcShortAddr = 0x%04x, want 0x0800", ctx.SrcShortAddr)
	}
	if ctx.DstShortAddr != 0x0400 {
		t.Errorf("DstShortAddr = 0x%04x, want 0x0400", ctx.DstShortAddr)
	}
	if !ctx.AckRequest {
		t.Error("AckRequest = false, want true")
	}

	// The MAC payload should be valid 6LoWPAN. Verify it starts with
	// an IPHC dispatch.
	macPayload := frame[headerLen:]
	if !lowpan.IsLowpanHc(macPayload) {
		t.Fatalf("MAC payload does not start with IPHC dispatch: 0x%02x 0x%02x",
			macPayload[0], macPayload[1])
	}

	// Decompress to verify round-trip.
	macAddrs := lowpan.AddressContext{
		SrcExtAddr: srcExt,
		DstExtAddr: dstExt,
	}
	ipv6Raw, consumed, _, err := lowpan.DecompressHeader(macPayload, macAddrs, nil)
	if err != nil {
		t.Fatalf("DecompressHeader() error: %v", err)
	}

	hdr := ip6.HeaderFromBytes(ipv6Raw)
	if hdr.GetHopLimit() != 64 {
		t.Errorf("HopLimit = %d, want 64", hdr.GetHopLimit())
	}
	if hdr.GetSource() != ip6.Address(srcAddr) {
		t.Errorf("Source = %v, want %v", hdr.GetSource(), srcAddr)
	}
	if hdr.GetDestination() != ip6.Address(dstAddr) {
		t.Errorf("Destination = %v, want %v", hdr.GetDestination(), dstAddr)
	}

	// The NH should be compressed (NH=0 means NHC follows).
	remaining := macPayload[consumed:]

	// Decompress UDP header.
	udpHdr, udpConsumed, err := lowpan.DecompressUDPHeader(remaining)
	if err != nil {
		t.Fatalf("DecompressUDPHeader() error: %v", err)
	}

	srcPort := uint16(udpHdr[0])<<8 | uint16(udpHdr[1])
	dstPort := uint16(udpHdr[2])<<8 | uint16(udpHdr[3])
	if srcPort != 19788 {
		t.Errorf("srcPort = %d, want 19788", srcPort)
	}
	if dstPort != 19788 {
		t.Errorf("dstPort = %d, want 19788", dstPort)
	}

	// The remaining data after UDP header should be our payload.
	appPayload := remaining[udpConsumed:]
	if string(appPayload) != "hello" {
		t.Errorf("payload = %q, want %q", string(appPayload), "hello")
	}
}

// TestBuildTxFrame_ICMPv6 verifies frame construction for non-UDP
// protocols (ICMPv6) where the next header is carried inline.
func TestBuildTxFrame_ICMPv6(t *testing.T) {
	srcAddr := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dstAddr := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	// ICMPv6 Echo Request: type=128, code=0, checksum=0, id=1, seq=1
	icmpPayload := []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}

	meta := &TxMetadata{
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
		NextHeader:  ip6.ProtoICMPv6,
		HopLimit:    64,
		UseSrcShort: true,
		UseDstShort: true,
		PanId:       0xABCD,
	}

	msg := NewTxMessageWithMetadata(icmpPayload, 0xFFFF, 0x0800, meta)
	frame, err := BuildTxFrame(msg, 7)
	if err != nil {
		t.Fatalf("BuildTxFrame() error: %v", err)
	}

	// Parse MAC header.
	framer := NewFramer()
	_, headerLen, err := framer.ParseFrameHeader(frame)
	if err != nil {
		t.Fatalf("ParseFrameHeader() error: %v", err)
	}

	macPayload := frame[headerLen:]
	if !lowpan.IsLowpanHc(macPayload) {
		t.Fatalf("not IPHC: 0x%02x 0x%02x", macPayload[0], macPayload[1])
	}

	// Decompress.
	macAddrs := lowpan.AddressContext{}
	ipv6Raw, consumed, _, err := lowpan.DecompressHeader(macPayload, macAddrs, nil)
	if err != nil {
		t.Fatalf("DecompressHeader() error: %v", err)
	}

	hdr := ip6.HeaderFromBytes(ipv6Raw)
	// For ICMPv6, NH is carried inline (not compressed).
	if hdr.GetNextHeader() != ip6.ProtoICMPv6 {
		t.Errorf("NextHeader = %d, want %d", hdr.GetNextHeader(), ip6.ProtoICMPv6)
	}

	// Remaining bytes should be the ICMPv6 payload.
	remaining := macPayload[consumed:]
	if len(remaining) != len(icmpPayload) {
		t.Fatalf("remaining len = %d, want %d", len(remaining), len(icmpPayload))
	}
	if remaining[0] != 0x80 {
		t.Errorf("ICMPv6 type = 0x%02x, want 0x80", remaining[0])
	}
}

// TestBuildTxFrame_NoMetadata verifies that BuildTxFrame returns an
// error when called with a TxMessage that has no metadata.
func TestBuildTxFrame_NoMetadata(t *testing.T) {
	msg := NewTxMessage([]byte{0x01}, 0x0400, 0x0800)
	_, err := BuildTxFrame(msg, 0)
	if err == nil {
		t.Fatal("expected error for nil Metadata, got nil")
	}
}

// TestBuildTxFrame_WithSecurity verifies that MAC security headers are
// included when SecurityEnabled is set.
func TestBuildTxFrame_WithSecurity(t *testing.T) {
	meta := &TxMetadata{
		SrcAddr:         [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DstAddr:         [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		SrcPort:         19788,
		DstPort:         19788,
		NextHeader:      ip6.ProtoUDP,
		HopLimit:        64,
		UseSrcShort:     true,
		UseDstShort:     true,
		PanId:           0x1234,
		SecurityEnabled: true,
		Security: SecurityMaterial{
			KeyIdMode:    1,
			KeyId:        1,
			FrameCounter: 42,
		},
	}

	msg := NewTxMessageWithMetadata([]byte{0xAA}, 0x0400, 0x0800, meta)
	frame, err := BuildTxFrame(msg, 10)
	if err != nil {
		t.Fatalf("BuildTxFrame() error: %v", err)
	}

	framer := NewFramer()
	ctx, _, err := framer.ParseFrameHeader(frame)
	if err != nil {
		t.Fatalf("ParseFrameHeader() error: %v", err)
	}

	if !ctx.SecurityEnabled {
		t.Error("SecurityEnabled = false, want true")
	}
	if ctx.Security.KeyIdMode != 1 {
		t.Errorf("KeyIdMode = %d, want 1", ctx.Security.KeyIdMode)
	}
	if ctx.Security.KeyId != 1 {
		t.Errorf("KeyId = %d, want 1", ctx.Security.KeyId)
	}
	if ctx.Security.FrameCounter != 42 {
		t.Errorf("FrameCounter = %d, want 42", ctx.Security.FrameCounter)
	}
}

// TestBuildTxFrame_ExtendedAddresses verifies frame building with
// extended (8-byte) MAC addresses.
func TestBuildTxFrame_ExtendedAddresses(t *testing.T) {
	srcExt := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	dstExt := [8]byte{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11}

	meta := &TxMetadata{
		SrcAddr:     [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DstAddr:     [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		NextHeader:  ip6.ProtoICMPv6,
		HopLimit:    255,
		SrcExtAddr:  srcExt,
		DstExtAddr:  dstExt,
		UseSrcShort: false, // use extended
		UseDstShort: false, // use extended
		PanId:       0x5678,
	}

	msg := NewTxMessageWithMetadata([]byte{0xFF}, 0x0400, 0x0800, meta)
	frame, err := BuildTxFrame(msg, 99)
	if err != nil {
		t.Fatalf("BuildTxFrame() error: %v", err)
	}

	framer := NewFramer()
	ctx, _, err := framer.ParseFrameHeader(frame)
	if err != nil {
		t.Fatalf("ParseFrameHeader() error: %v", err)
	}

	if ctx.UseSrcShort {
		t.Error("UseSrcShort = true, want false")
	}
	if ctx.UseDstShort {
		t.Error("UseDstShort = true, want false")
	}
	if ctx.SrcExtAddr != srcExt {
		t.Errorf("SrcExtAddr = %v, want %v", ctx.SrcExtAddr, srcExt)
	}
	if ctx.DstExtAddr != dstExt {
		t.Errorf("DstExtAddr = %v, want %v", ctx.DstExtAddr, dstExt)
	}
}

// TestBuildUDPMetadata verifies the convenience function.
func TestBuildUDPMetadata(t *testing.T) {
	src := [16]byte{1}
	dst := [16]byte{2}
	meta := BuildUDPMetadata(src, dst, 1234, 5678, 128)

	if meta.NextHeader != ip6.ProtoUDP {
		t.Errorf("NextHeader = %d, want %d", meta.NextHeader, ip6.ProtoUDP)
	}
	if meta.SrcPort != 1234 {
		t.Errorf("SrcPort = %d, want 1234", meta.SrcPort)
	}
	if meta.DstPort != 5678 {
		t.Errorf("DstPort = %d, want 5678", meta.DstPort)
	}
	if meta.HopLimit != 128 {
		t.Errorf("HopLimit = %d, want 128", meta.HopLimit)
	}
	if meta.SrcAddr != src {
		t.Error("SrcAddr mismatch")
	}
}
