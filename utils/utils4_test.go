// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"bytes"
	"encoding/binary"
	"math"
	"slices"
	"testing"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/radio"
)

// ============================================================================
// History Tracker TLV Tests
// ============================================================================

func TestMarshalParseAnswerTlv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		index  uint16
		isLast bool
	}{
		{"index_0_not_last", 0, false},
		{"index_0_last", 0, true},
		{"index_42_not_last", 42, false},
		{"index_max_last", 0x7FFF, true},
		{"index_1000_not_last", 1000, false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			original := &AnswerTlv{Index: tc.index, IsLast: tc.isLast}
			data := MarshalAnswerTlv(original)

			// Check TLV header
			if data[0] != HTTlvAnswer {
				t.Errorf("type = %d, want %d", data[0], HTTlvAnswer)
			}
			if data[1] != answerValueSize {
				t.Errorf("length = %d, want %d", data[1], answerValueSize)
			}

			// Parse back
			parsed, err := ParseAnswerTlv(data[htTlvHeaderSize:])
			if err != nil {
				t.Fatalf("ParseAnswerTlv error: %v", err)
			}
			if parsed.Index != tc.index {
				t.Errorf("Index = %d, want %d", parsed.Index, tc.index)
			}
			if parsed.IsLast != tc.isLast {
				t.Errorf("IsLast = %v, want %v", parsed.IsLast, tc.isLast)
			}
		})
	}
}

func TestParseAnswerTlvTooShort(t *testing.T) {
	t.Parallel()

	_, err := ParseAnswerTlv([]byte{0x00})
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

func TestMarshalParseRequestTlv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		tlvType     uint8
		numEntries  uint16
		maxEntryAge uint32
	}{
		{"network_info_all", HTTlvNetworkInfo, 0, 0},
		{"network_info_limited", HTTlvNetworkInfo, 100, 60000},
		{"max_values", 0xFF, 0xFFFF, 0xFFFFFFFF},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			original := &RequestTlv{
				TlvType:     tc.tlvType,
				NumEntries:  tc.numEntries,
				MaxEntryAge: tc.maxEntryAge,
			}
			data := MarshalRequestTlv(original)

			if data[0] != HTTlvRequest {
				t.Errorf("type = %d, want %d", data[0], HTTlvRequest)
			}

			parsed, err := ParseRequestTlv(data[htTlvHeaderSize:])
			if err != nil {
				t.Fatalf("ParseRequestTlv error: %v", err)
			}
			if parsed.TlvType != tc.tlvType {
				t.Errorf("TlvType = %d, want %d", parsed.TlvType, tc.tlvType)
			}
			if parsed.NumEntries != tc.numEntries {
				t.Errorf("NumEntries = %d, want %d", parsed.NumEntries, tc.numEntries)
			}
			if parsed.MaxEntryAge != tc.maxEntryAge {
				t.Errorf("MaxEntryAge = %d, want %d", parsed.MaxEntryAge, tc.maxEntryAge)
			}
		})
	}
}

func TestParseRequestTlvTooShort(t *testing.T) {
	t.Parallel()

	_, err := ParseRequestTlv([]byte{0x00, 0x01})
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

func TestIsValidRequestTlv(t *testing.T) {
	t.Parallel()

	if IsValidRequestTlv([]byte{}) {
		t.Error("empty value should be invalid")
	}
	if IsValidRequestTlv(make([]byte, requestValueSize-1)) {
		t.Error("short value should be invalid")
	}
	if !IsValidRequestTlv(make([]byte, requestValueSize)) {
		t.Error("exact-size value should be valid")
	}
	if !IsValidRequestTlv(make([]byte, requestValueSize+10)) {
		t.Error("oversized value should be valid")
	}
}

func TestMarshalParseNetworkInfoTlv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		entryAge    uint32
		role        uint8
		mode        uint8
		rloc16      uint16
		partitionID uint32
	}{
		{"zeros", 0, 0, 0, 0, 0},
		{"leader", 5000, 4, 0x0F, 0xFC00, 12345},
		{"router", 120000, 3, 0x0D, 0x1400, 67890},
		{"max_values", math.MaxUint32, math.MaxUint8, math.MaxUint8, math.MaxUint16, math.MaxUint32},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			original := &NetworkInfoTlv{
				EntryAge:    tc.entryAge,
				Role:        tc.role,
				Mode:        tc.mode,
				Rloc16:      tc.rloc16,
				PartitionId: tc.partitionID,
			}
			data := MarshalNetworkInfoTlv(original)

			if data[0] != HTTlvNetworkInfo {
				t.Errorf("type = %d, want %d", data[0], HTTlvNetworkInfo)
			}

			parsed, err := ParseNetworkInfoTlv(data[htTlvHeaderSize:])
			if err != nil {
				t.Fatalf("ParseNetworkInfoTlv error: %v", err)
			}
			if parsed.EntryAge != tc.entryAge {
				t.Errorf("EntryAge = %d, want %d", parsed.EntryAge, tc.entryAge)
			}
			if parsed.Role != tc.role {
				t.Errorf("Role = %d, want %d", parsed.Role, tc.role)
			}
			if parsed.Mode != tc.mode {
				t.Errorf("Mode = %d, want %d", parsed.Mode, tc.mode)
			}
			if parsed.Rloc16 != tc.rloc16 {
				t.Errorf("Rloc16 = 0x%04X, want 0x%04X", parsed.Rloc16, tc.rloc16)
			}
			if parsed.PartitionId != tc.partitionID {
				t.Errorf("PartitionId = %d, want %d", parsed.PartitionId, tc.partitionID)
			}
		})
	}
}

func TestParseNetworkInfoTlvTooShort(t *testing.T) {
	t.Parallel()

	_, err := ParseNetworkInfoTlv(make([]byte, networkInfoValueSize-1))
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

func TestIsValidNetworkInfoTlv(t *testing.T) {
	t.Parallel()

	if IsValidNetworkInfoTlv([]byte{}) {
		t.Error("empty should be invalid")
	}
	if !IsValidNetworkInfoTlv(make([]byte, networkInfoValueSize)) {
		t.Error("exact-size should be valid")
	}
}

func TestMarshalEmptyNetworkInfoTlv(t *testing.T) {
	t.Parallel()

	data := MarshalEmptyNetworkInfoTlv()
	if len(data) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(data))
	}
	if data[0] != HTTlvNetworkInfo {
		t.Errorf("type = %d, want %d", data[0], HTTlvNetworkInfo)
	}
	if data[1] != 0 {
		t.Errorf("length = %d, want 0", data[1])
	}
}

func TestMarshalParseQueryIDTlv(t *testing.T) {
	t.Parallel()

	tests := []uint16{0, 1, 42, 0xFFFF}
	for _, id := range tests {
		data := MarshalQueryIDTlv(id)
		if data[0] != HTTlvQueryID {
			t.Errorf("type = %d, want %d", data[0], HTTlvQueryID)
		}
		parsed, err := ParseQueryIDTlv(data[htTlvHeaderSize:])
		if err != nil {
			t.Fatalf("ParseQueryIDTlv(%d) error: %v", id, err)
		}
		if parsed != id {
			t.Errorf("ParseQueryIDTlv = %d, want %d", parsed, id)
		}
	}
}

func TestParseQueryIDTlvTooShort(t *testing.T) {
	t.Parallel()

	_, err := ParseQueryIDTlv([]byte{0x00})
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

func TestParseHTTlv(t *testing.T) {
	t.Parallel()

	// Build a buffer with a QueryID TLV followed by an AnswerTlv.
	qid := MarshalQueryIDTlv(0x1234)
	ans := MarshalAnswerTlv(&AnswerTlv{Index: 5, IsLast: true})
	buf := slices.Concat(qid, ans)

	// Parse first TLV.
	typ, value, consumed, err := ParseHTTlv(buf)
	if err != nil {
		t.Fatalf("ParseHTTlv error: %v", err)
	}
	if typ != HTTlvQueryID {
		t.Errorf("type = %d, want %d", typ, HTTlvQueryID)
	}
	if consumed != len(qid) {
		t.Errorf("consumed = %d, want %d", consumed, len(qid))
	}
	parsedID, _ := ParseQueryIDTlv(value)
	if parsedID != 0x1234 {
		t.Errorf("queryID = 0x%04X, want 0x1234", parsedID)
	}

	// Parse second TLV.
	typ, value, consumed, err = ParseHTTlv(buf[len(qid):])
	if err != nil {
		t.Fatalf("ParseHTTlv error: %v", err)
	}
	if typ != HTTlvAnswer {
		t.Errorf("type = %d, want %d", typ, HTTlvAnswer)
	}
	if consumed != len(ans) {
		t.Errorf("consumed = %d, want %d", consumed, len(ans))
	}
	parsedAns, _ := ParseAnswerTlv(value)
	if parsedAns.Index != 5 || !parsedAns.IsLast {
		t.Errorf("answer = %+v, want Index=5 IsLast=true", parsedAns)
	}
}

func TestParseHTTlvErrors(t *testing.T) {
	t.Parallel()

	// Too short for header.
	_, _, _, err := ParseHTTlv([]byte{0x00})
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse for short header, got %v", err)
	}

	// Length exceeds available data.
	_, _, _, err = ParseHTTlv([]byte{0x00, 0x05, 0x01})
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse for truncated value, got %v", err)
	}
}

func TestNetworkInfoTlvWireFormat(t *testing.T) {
	t.Parallel()

	// Verify big-endian encoding matches expectations.
	info := &NetworkInfoTlv{
		EntryAge:    0x01020304,
		Role:        0x05,
		Mode:        0x06,
		Rloc16:      0x0708,
		PartitionId: 0x090A0B0C,
	}
	data := MarshalNetworkInfoTlv(info)
	value := data[htTlvHeaderSize:]

	expected := []byte{
		0x01, 0x02, 0x03, 0x04, // EntryAge
		0x05,       // Role
		0x06,       // Mode
		0x07, 0x08, // Rloc16
		0x09, 0x0A, 0x0B, 0x0C, // PartitionId
	}
	if !bytes.Equal(value, expected) {
		t.Errorf("wire format:\n  got  %X\n  want %X", value, expected)
	}
}

func TestAnswerTlvBitLayout(t *testing.T) {
	t.Parallel()

	// IsLast=true, Index=0x1234 (masked to 14 bits = 0x1234)
	a := &AnswerTlv{Index: 0x1234, IsLast: true}
	data := MarshalAnswerTlv(a)
	value := data[htTlvHeaderSize:]

	// Wire format: Expected: 0x8000 | 0x1234 = 0x9234
	expected := uint16(0x9234)
	got := binary.BigEndian.Uint16(value)
	if got != expected {
		t.Errorf("flags+index = 0x%04X, want 0x%04X", got, expected)
	}
}

// ============================================================================
// Power Calibration Tests
// ============================================================================

func TestNewPowerCalibration(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()
	if pc == nil {
		t.Fatal("NewPowerCalibration returned nil")
	}
}

func TestPowerCalibrationAddAndGet(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()

	// Set target power for channel 15.
	err := pc.SetChannelTargetPower(15, 2000)
	if err != nil {
		t.Fatalf("SetChannelTargetPower error: %v", err)
	}

	// Add calibrated powers for channel 15.
	err = pc.AddCalibratedPower(15, 1000, []byte{0x10, 0x20})
	if err != nil {
		t.Fatalf("AddCalibratedPower(1000) error: %v", err)
	}
	err = pc.AddCalibratedPower(15, 2000, []byte{0x30, 0x40})
	if err != nil {
		t.Fatalf("AddCalibratedPower(2000) error: %v", err)
	}
	err = pc.AddCalibratedPower(15, 3000, []byte{0x50, 0x60})
	if err != nil {
		t.Fatalf("AddCalibratedPower(3000) error: %v", err)
	}

	// Get power settings — should pick actualPower=2000 (closest <= target).
	settings, err := pc.GetPowerSettings(15)
	if err != nil {
		t.Fatalf("GetPowerSettings error: %v", err)
	}
	if settings.TargetPower != 2000 {
		t.Errorf("TargetPower = %d, want 2000", settings.TargetPower)
	}
	if settings.ActualPower != 2000 {
		t.Errorf("ActualPower = %d, want 2000", settings.ActualPower)
	}
	if !bytes.Equal(settings.RawPower, []byte{0x30, 0x40}) {
		t.Errorf("RawPower = %X, want 3040", settings.RawPower)
	}
}

func TestPowerCalibrationSelectsBestMatch(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()
	if err := pc.SetChannelTargetPower(11, 2500); err != nil {
		t.Fatal(err)
	}
	// Add entries: 1000, 2000, 3000.
	for _, ap := range []int16{1000, 2000, 3000} {
		if err := pc.AddCalibratedPower(11, ap, []byte{byte(ap / 1000)}); err != nil {
			t.Fatal(err)
		}
	}

	settings, err := pc.GetPowerSettings(11)
	if err != nil {
		t.Fatalf("GetPowerSettings error: %v", err)
	}
	// Target=2500, best match <= target is 2000.
	if settings.ActualPower != 2000 {
		t.Errorf("ActualPower = %d, want 2000", settings.ActualPower)
	}
}

func TestPowerCalibrationFallbackToMinPower(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()
	if err := pc.SetChannelTargetPower(11, 500); err != nil {
		t.Fatal(err)
	}
	// All entries are above target.
	for _, ap := range []int16{1000, 2000, 3000} {
		if err := pc.AddCalibratedPower(11, ap, []byte{byte(ap / 1000)}); err != nil {
			t.Fatal(err)
		}
	}

	settings, err := pc.GetPowerSettings(11)
	if err != nil {
		t.Fatalf("GetPowerSettings error: %v", err)
	}
	// No entry <= target, so fall back to minimum (1000).
	if settings.ActualPower != 1000 {
		t.Errorf("ActualPower = %d, want 1000", settings.ActualPower)
	}
}

func TestPowerCalibrationInvalidChannel(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()

	err := pc.SetChannelTargetPower(0, 1000)
	if err != errors.ErrInvalidArgs {
		t.Errorf("SetChannelTargetPower(0) = %v, want ErrInvalidArgs", err)
	}

	err = pc.SetChannelTargetPower(27, 1000)
	if err != errors.ErrInvalidArgs {
		t.Errorf("SetChannelTargetPower(27) = %v, want ErrInvalidArgs", err)
	}

	err = pc.AddCalibratedPower(5, 1000, []byte{0x01})
	if err != errors.ErrInvalidArgs {
		t.Errorf("AddCalibratedPower(ch=5) = %v, want ErrInvalidArgs", err)
	}

	_, err = pc.GetPowerSettings(30)
	if err != errors.ErrInvalidArgs {
		t.Errorf("GetPowerSettings(30) = %v, want ErrInvalidArgs", err)
	}
}

func TestPowerCalibrationDuplicateActualPower(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()
	if err := pc.AddCalibratedPower(11, 1000, []byte{0x01}); err != nil {
		t.Fatal(err)
	}
	err := pc.AddCalibratedPower(11, 1000, []byte{0x02})
	if err != errors.ErrInvalidArgs {
		t.Errorf("duplicate actualPower = %v, want ErrInvalidArgs", err)
	}
}

func TestPowerCalibrationTableFull(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()
	for i := 0; i < MaxCalibratedPowerEntries; i++ {
		if err := pc.AddCalibratedPower(11, int16(i*100), []byte{byte(i)}); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	err := pc.AddCalibratedPower(11, int16(MaxCalibratedPowerEntries*100), []byte{0xFF})
	if err != errors.ErrNoBufs {
		t.Errorf("overflow = %v, want ErrNoBufs", err)
	}
}

func TestPowerCalibrationClear(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()
	if err := pc.AddCalibratedPower(11, 1000, []byte{0x01}); err != nil {
		t.Fatal(err)
	}
	pc.ClearCalibratedPowers()

	count, err := pc.GetCalibratedPowerCount(11)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("count after clear = %d, want 0", count)
	}
}

func TestPowerCalibrationNoTargetPower(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()
	if err := pc.AddCalibratedPower(11, 1000, []byte{0x01}); err != nil {
		t.Fatal(err)
	}

	// No target power set — should return ErrNotFound.
	_, err := pc.GetPowerSettings(11)
	if err != errors.ErrNotFound {
		t.Errorf("GetPowerSettings without target = %v, want ErrNotFound", err)
	}
}

func TestPowerCalibrationNoCalibratedPowers(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()
	if err := pc.SetChannelTargetPower(11, 1000); err != nil {
		t.Fatal(err)
	}

	// Target set but no calibration data — should return ErrNotFound.
	_, err := pc.GetPowerSettings(11)
	if err != errors.ErrNotFound {
		t.Errorf("GetPowerSettings without calibration = %v, want ErrNotFound", err)
	}
}

func TestPowerCalibrationEmptyRawPower(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()
	err := pc.AddCalibratedPower(11, 1000, []byte{})
	if err != errors.ErrInvalidArgs {
		t.Errorf("empty raw power = %v, want ErrInvalidArgs", err)
	}
}

func TestPowerCalibrationRawPowerTooLong(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()
	rawPower := make([]byte, MaxRawPowerSettingSize+1)
	err := pc.AddCalibratedPower(11, 1000, rawPower)
	if err != errors.ErrInvalidArgs {
		t.Errorf("oversized raw power = %v, want ErrInvalidArgs", err)
	}
}

func TestPowerCalibrationGetTargetPower(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()

	// Not set yet.
	_, err := pc.GetChannelTargetPower(11)
	if err != errors.ErrNotFound {
		t.Errorf("unset target = %v, want ErrNotFound", err)
	}

	if err := pc.SetChannelTargetPower(11, 1500); err != nil {
		t.Fatal(err)
	}

	tp, err := pc.GetChannelTargetPower(11)
	if err != nil {
		t.Fatalf("GetChannelTargetPower error: %v", err)
	}
	if tp != 1500 {
		t.Errorf("target power = %d, want 1500", tp)
	}

	// Invalid channel.
	_, err = pc.GetChannelTargetPower(0)
	if err != errors.ErrInvalidArgs {
		t.Errorf("invalid channel = %v, want ErrInvalidArgs", err)
	}
}

func TestPowerCalibrationCacheInvalidation(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()
	if err := pc.SetChannelTargetPower(15, 2000); err != nil {
		t.Fatal(err)
	}
	if err := pc.AddCalibratedPower(15, 1000, []byte{0x01}); err != nil {
		t.Fatal(err)
	}

	// First query caches the result.
	s1, err := pc.GetPowerSettings(15)
	if err != nil {
		t.Fatal(err)
	}
	if s1.ActualPower != 1000 {
		t.Fatalf("first query ActualPower = %d, want 1000", s1.ActualPower)
	}

	// Add a better entry.
	if err := pc.AddCalibratedPower(15, 2000, []byte{0x02}); err != nil {
		t.Fatal(err)
	}

	// Should find the new entry.
	s2, err := pc.GetPowerSettings(15)
	if err != nil {
		t.Fatal(err)
	}
	if s2.ActualPower != 2000 {
		t.Errorf("after add ActualPower = %d, want 2000", s2.ActualPower)
	}

	// Changing target power also invalidates cache.
	if err := pc.SetChannelTargetPower(15, 1500); err != nil {
		t.Fatal(err)
	}
	s3, err := pc.GetPowerSettings(15)
	if err != nil {
		t.Fatal(err)
	}
	if s3.ActualPower != 1000 {
		t.Errorf("after target change ActualPower = %d, want 1000", s3.ActualPower)
	}
}

func TestPowerCalibrationMultipleChannels(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()

	for ch := radio.Channel24GHzMin; ch <= radio.Channel24GHzMax; ch++ {
		if err := pc.SetChannelTargetPower(ch, int16(ch)*100); err != nil {
			t.Fatalf("ch=%d SetChannelTargetPower: %v", ch, err)
		}
		if err := pc.AddCalibratedPower(ch, int16(ch)*100, []byte{ch}); err != nil {
			t.Fatalf("ch=%d AddCalibratedPower: %v", ch, err)
		}
	}

	for ch := radio.Channel24GHzMin; ch <= radio.Channel24GHzMax; ch++ {
		s, err := pc.GetPowerSettings(ch)
		if err != nil {
			t.Fatalf("ch=%d GetPowerSettings: %v", ch, err)
		}
		if s.ActualPower != int16(ch)*100 {
			t.Errorf("ch=%d ActualPower = %d, want %d", ch, s.ActualPower, int16(ch)*100)
		}
		if !bytes.Equal(s.RawPower, []byte{ch}) {
			t.Errorf("ch=%d RawPower = %X, want %02X", ch, s.RawPower, ch)
		}
	}
}

func TestPowerCalibrationDisableChannel(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()
	// First set a valid target and calibrated power so the channel works.
	if err := pc.SetChannelTargetPower(11, 2000); err != nil {
		t.Fatal(err)
	}
	if err := pc.AddCalibratedPower(11, 1000, []byte{0x01}); err != nil {
		t.Fatal(err)
	}

	// Verify it works before disabling.
	s, err := pc.GetPowerSettings(11)
	if err != nil {
		t.Fatalf("GetPowerSettings before disable: %v", err)
	}
	if s.ActualPower != 1000 {
		t.Errorf("ActualPower = %d, want 1000", s.ActualPower)
	}

	// Setting target to MaxInt16 disables the channel (treated as invalidPower).
	if err := pc.SetChannelTargetPower(11, math.MaxInt16); err != nil {
		t.Fatal(err)
	}

	// GetPowerSettings should now return ErrNotFound since the channel is disabled.
	_, err = pc.GetPowerSettings(11)
	if err != errors.ErrNotFound {
		t.Errorf("GetPowerSettings after disable = %v, want ErrNotFound", err)
	}
}

func TestPowerCalibrationGetCountInvalidChannel(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()
	_, err := pc.GetCalibratedPowerCount(0)
	if err != errors.ErrInvalidArgs {
		t.Errorf("invalid channel count = %v, want ErrInvalidArgs", err)
	}
}

func TestPowerCalibrationRawPowerIsCopied(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()
	raw := []byte{0x01, 0x02, 0x03}
	if err := pc.AddCalibratedPower(11, 1000, raw); err != nil {
		t.Fatal(err)
	}

	// Modify original — should not affect stored value.
	raw[0] = 0xFF

	if err := pc.SetChannelTargetPower(11, 1000); err != nil {
		t.Fatal(err)
	}
	s, err := pc.GetPowerSettings(11)
	if err != nil {
		t.Fatal(err)
	}
	if s.RawPower[0] != 0x01 {
		t.Error("stored raw power was affected by modifying original slice")
	}

	// Modify returned value — should not affect stored value.
	s.RawPower[0] = 0xAA
	s2, err := pc.GetPowerSettings(11)
	if err != nil {
		t.Fatal(err)
	}
	if s2.RawPower[0] != 0x01 {
		t.Error("stored raw power was affected by modifying returned slice")
	}
}

func TestPowerCalibrationNegativePower(t *testing.T) {
	t.Parallel()

	pc := NewPowerCalibration()
	if err := pc.SetChannelTargetPower(11, -500); err != nil {
		t.Fatal(err)
	}
	if err := pc.AddCalibratedPower(11, -1000, []byte{0x01}); err != nil {
		t.Fatal(err)
	}
	if err := pc.AddCalibratedPower(11, -500, []byte{0x02}); err != nil {
		t.Fatal(err)
	}
	if err := pc.AddCalibratedPower(11, 0, []byte{0x03}); err != nil {
		t.Fatal(err)
	}

	s, err := pc.GetPowerSettings(11)
	if err != nil {
		t.Fatal(err)
	}
	// Target=-500, best match <= target is -500.
	if s.ActualPower != -500 {
		t.Errorf("ActualPower = %d, want -500", s.ActualPower)
	}
}

func TestHTTlvConstants(t *testing.T) {
	t.Parallel()

	if HTTlvQueryID != 0 {
		t.Errorf("HTTlvQueryID = %d, want 0", HTTlvQueryID)
	}
	if HTTlvAnswer != 1 {
		t.Errorf("HTTlvAnswer = %d, want 1", HTTlvAnswer)
	}
	if HTTlvRequest != 2 {
		t.Errorf("HTTlvRequest = %d, want 2", HTTlvRequest)
	}
	if HTTlvNetworkInfo != 3 {
		t.Errorf("HTTlvNetworkInfo = %d, want 3", HTTlvNetworkInfo)
	}
}
