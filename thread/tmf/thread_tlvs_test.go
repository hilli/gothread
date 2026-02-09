// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

import (
	"encoding/binary"
	"errors"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/tlv"
)

// ---------------------------------------------------------------------------
// Address Solicit Request
// ---------------------------------------------------------------------------

func TestMarshalParseAddrSolicitRequest(t *testing.T) {
	tests := []struct {
		name string
		req  AddrSolicitRequest
	}{
		{
			name: "without RLOC16",
			req: AddrSolicitRequest{
				ExtAddress: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				Status:     mle.UpgradeReasonTooFewRouters,
			},
		},
		{
			name: "with RLOC16",
			req: AddrSolicitRequest{
				ExtAddress: types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22},
				HasRLOC16:  true,
				RLOC16:     0x7C00,
				Status:     mle.UpgradeReasonHaveChildIDRequest,
			},
		},
		{
			name: "border router request reason",
			req: AddrSolicitRequest{
				ExtAddress: types.ExtAddress{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80},
				Status:     mle.UpgradeReasonBorderRouterRequest,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := MarshalAddrSolicitRequest(&tt.req)
			got, err := ParseAddrSolicitRequest(data)
			if err != nil {
				t.Fatalf("ParseAddrSolicitRequest: %v", err)
			}
			if got.ExtAddress != tt.req.ExtAddress {
				t.Errorf("ExtAddress = %x, want %x", got.ExtAddress, tt.req.ExtAddress)
			}
			if got.Status != tt.req.Status {
				t.Errorf("Status = %d, want %d", got.Status, tt.req.Status)
			}
			if got.HasRLOC16 != tt.req.HasRLOC16 {
				t.Errorf("HasRLOC16 = %v, want %v", got.HasRLOC16, tt.req.HasRLOC16)
			}
			if tt.req.HasRLOC16 && got.RLOC16 != tt.req.RLOC16 {
				t.Errorf("RLOC16 = 0x%04X, want 0x%04X", got.RLOC16, tt.req.RLOC16)
			}
		})
	}
}

func TestParseAddrSolicitRequestErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty data",
			data: nil,
		},
		{
			name: "truncated TLV",
			data: []byte{ThreadTLVExtMACAddress, 8, 1, 2},
		},
		{
			name: "missing ExtMACAddress",
			data: tlv.TLV{Type: ThreadTLVStatus, Value: []byte{2}}.Marshal(),
		},
		{
			name: "missing Status",
			data: tlv.TLV{
				Type:  ThreadTLVExtMACAddress,
				Value: make([]byte, types.ExtAddressSize),
			}.Marshal(),
		},
		{
			name: "wrong ExtMACAddress length",
			data: func() []byte {
				var buf []byte
				buf = append(buf, tlv.TLV{Type: ThreadTLVExtMACAddress, Value: []byte{1, 2, 3}}.Marshal()...)
				buf = append(buf, tlv.TLV{Type: ThreadTLVStatus, Value: []byte{2}}.Marshal()...)
				return buf
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAddrSolicitRequest(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, goterrors.ErrParse) {
				t.Errorf("error = %v, want ErrParse", err)
			}
		})
	}
}

func TestMarshalAddrSolicitRequestWireFormat(t *testing.T) {
	req := AddrSolicitRequest{
		ExtAddress: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Status:     mle.UpgradeReasonTooFewRouters,
	}

	data := MarshalAddrSolicitRequest(&req)
	tlvs, err := tlv.ParseAll(data)
	if err != nil {
		t.Fatalf("ParseAll: %v", err)
	}

	// Should have exactly 2 TLVs: ExtMACAddress + Status.
	if len(tlvs) != 2 {
		t.Fatalf("got %d TLVs, want 2", len(tlvs))
	}

	extTLV := tlv.FindByType(tlvs, ThreadTLVExtMACAddress)
	if extTLV == nil {
		t.Fatal("missing ExtMACAddress TLV")
	}
	if len(extTLV.Value) != 8 {
		t.Errorf("ExtMACAddress value length = %d, want 8", len(extTLV.Value))
	}

	statusTLV := tlv.FindByType(tlvs, ThreadTLVStatus)
	if statusTLV == nil {
		t.Fatal("missing Status TLV")
	}
	if len(statusTLV.Value) != 1 || statusTLV.Value[0] != uint8(mle.UpgradeReasonTooFewRouters) {
		t.Errorf("Status value = %v, want [%d]", statusTLV.Value, mle.UpgradeReasonTooFewRouters)
	}
}

// ---------------------------------------------------------------------------
// Address Solicit Response
// ---------------------------------------------------------------------------

func TestMarshalParseAddrSolicitResponse(t *testing.T) {
	idSet := mle.RouterIDSet{}
	idSet.Add(0)
	idSet.Add(5)
	idSet.Add(62)

	tests := []struct {
		name string
		resp AddrSolicitResponse
	}{
		{
			name: "success",
			resp: AddrSolicitResponse{
				Status:           AddrSolicitSuccess,
				HasRLOC16:        true,
				RLOC16:           0x1400,
				HasRouterMask:    true,
				RouterIDSequence: 42,
				RouterIDSet:      idSet,
			},
		},
		{
			name: "no address available",
			resp: AddrSolicitResponse{
				Status: AddrSolicitNoAddressAvailable,
			},
		},
		{
			name: "unrecognized reason",
			resp: AddrSolicitResponse{
				Status: AddrSolicitUnrecognizedReason,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := MarshalAddrSolicitResponse(&tt.resp)
			got, err := ParseAddrSolicitResponse(data)
			if err != nil {
				t.Fatalf("ParseAddrSolicitResponse: %v", err)
			}
			if got.Status != tt.resp.Status {
				t.Errorf("Status = %d, want %d", got.Status, tt.resp.Status)
			}
			if tt.resp.Status == AddrSolicitSuccess {
				if !got.HasRLOC16 || got.RLOC16 != tt.resp.RLOC16 {
					t.Errorf("RLOC16 = (has=%v, 0x%04X), want (true, 0x%04X)",
						got.HasRLOC16, got.RLOC16, tt.resp.RLOC16)
				}
				if !got.HasRouterMask {
					t.Fatal("expected HasRouterMask = true")
				}
				if got.RouterIDSequence != tt.resp.RouterIDSequence {
					t.Errorf("RouterIDSequence = %d, want %d",
						got.RouterIDSequence, tt.resp.RouterIDSequence)
				}
				if got.RouterIDSet != tt.resp.RouterIDSet {
					t.Errorf("RouterIDSet = %x, want %x",
						got.RouterIDSet, tt.resp.RouterIDSet)
				}
			} else {
				if got.HasRLOC16 {
					t.Errorf("expected HasRLOC16 = false for status %d", tt.resp.Status)
				}
				if got.HasRouterMask {
					t.Errorf("expected HasRouterMask = false for status %d", tt.resp.Status)
				}
			}
		})
	}
}

func TestParseAddrSolicitResponseErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty data",
			data: nil,
		},
		{
			name: "truncated TLV",
			data: []byte{ThreadTLVStatus, 1},
		},
		{
			name: "missing Status TLV",
			data: func() []byte {
				rloc := [2]byte{}
				binary.BigEndian.PutUint16(rloc[:], 0x1400)
				return tlv.TLV{Type: ThreadTLVRLOC16, Value: rloc[:]}.Marshal()
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAddrSolicitResponse(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, goterrors.ErrParse) {
				t.Errorf("error = %v, want ErrParse", err)
			}
		})
	}
}

func TestAddrSolicitResponseSuccessWireFormat(t *testing.T) {
	idSet := mle.RouterIDSet{}
	idSet.Add(0)
	idSet.Add(10)

	resp := AddrSolicitResponse{
		Status:           AddrSolicitSuccess,
		HasRLOC16:        true,
		RLOC16:           mle.RLOC16FromRouterID(10),
		HasRouterMask:    true,
		RouterIDSequence: 7,
		RouterIDSet:      idSet,
	}

	data := MarshalAddrSolicitResponse(&resp)
	tlvs, err := tlv.ParseAll(data)
	if err != nil {
		t.Fatalf("ParseAll: %v", err)
	}

	// Should have 3 TLVs: Status + RLOC16 + RouterMask.
	if len(tlvs) != 3 {
		t.Fatalf("got %d TLVs, want 3", len(tlvs))
	}

	statusTLV := tlv.FindByType(tlvs, ThreadTLVStatus)
	if statusTLV == nil || statusTLV.Value[0] != 0 {
		t.Errorf("Status TLV missing or not success")
	}

	rloc16TLV := tlv.FindByType(tlvs, ThreadTLVRLOC16)
	if rloc16TLV == nil {
		t.Fatal("missing RLOC16 TLV")
	}
	gotRLOC := binary.BigEndian.Uint16(rloc16TLV.Value)
	if gotRLOC != resp.RLOC16 {
		t.Errorf("RLOC16 = 0x%04X, want 0x%04X", gotRLOC, resp.RLOC16)
	}

	maskTLV := tlv.FindByType(tlvs, ThreadTLVRouterMask)
	if maskTLV == nil {
		t.Fatal("missing RouterMask TLV")
	}
	if len(maskTLV.Value) != RouterMaskTLVSize {
		t.Fatalf("RouterMask value length = %d, want %d", len(maskTLV.Value), RouterMaskTLVSize)
	}
	if maskTLV.Value[0] != 7 {
		t.Errorf("RouterIDSequence = %d, want 7", maskTLV.Value[0])
	}
}

// ---------------------------------------------------------------------------
// Address Release Request
// ---------------------------------------------------------------------------

func TestMarshalParseAddrReleaseRequest(t *testing.T) {
	req := AddrReleaseRequest{
		RLOC16:     0x2800,
		ExtAddress: types.ExtAddress{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01},
	}

	data := MarshalAddrReleaseRequest(&req)
	got, err := ParseAddrReleaseRequest(data)
	if err != nil {
		t.Fatalf("ParseAddrReleaseRequest: %v", err)
	}
	if got.RLOC16 != req.RLOC16 {
		t.Errorf("RLOC16 = 0x%04X, want 0x%04X", got.RLOC16, req.RLOC16)
	}
	if got.ExtAddress != req.ExtAddress {
		t.Errorf("ExtAddress = %x, want %x", got.ExtAddress, req.ExtAddress)
	}
}

func TestParseAddrReleaseRequestErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty data",
			data: nil,
		},
		{
			name: "missing RLOC16",
			data: tlv.TLV{
				Type:  ThreadTLVExtMACAddress,
				Value: make([]byte, types.ExtAddressSize),
			}.Marshal(),
		},
		{
			name: "missing ExtMACAddress",
			data: func() []byte {
				rloc := [2]byte{}
				binary.BigEndian.PutUint16(rloc[:], 0x1400)
				return tlv.TLV{Type: ThreadTLVRLOC16, Value: rloc[:]}.Marshal()
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAddrReleaseRequest(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, goterrors.ErrParse) {
				t.Errorf("error = %v, want ErrParse", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AddrSolicitStatus.String
// ---------------------------------------------------------------------------

func TestAddrSolicitStatusString(t *testing.T) {
	tests := []struct {
		status AddrSolicitStatus
		want   string
	}{
		{AddrSolicitSuccess, "Success"},
		{AddrSolicitNoAddressAvailable, "NoAddressAvailable"},
		{AddrSolicitUnrecognizedReason, "UnrecognizedReason"},
		{AddrSolicitStatus(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.status.String(); got != tt.want {
			t.Errorf("AddrSolicitStatus(%d).String() = %q, want %q", tt.status, got, tt.want)
		}
	}
}
