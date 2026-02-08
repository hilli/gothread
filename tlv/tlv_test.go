package tlv

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseStandardTLV(t *testing.T) {
	// Type=1, Length=3, Value={0xaa, 0xbb, 0xcc}
	data := []byte{0x01, 0x03, 0xaa, 0xbb, 0xcc}
	got, n, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("Parse: bytes consumed = %d, want 5", n)
	}
	if got.Type != 1 {
		t.Errorf("Type = %d, want 1", got.Type)
	}
	if got.Length != 3 {
		t.Errorf("Length = %d, want 3", got.Length)
	}
	if !bytes.Equal(got.Value, []byte{0xaa, 0xbb, 0xcc}) {
		t.Errorf("Value = %x, want aabbcc", got.Value)
	}
}

func TestParseExtendedTLV(t *testing.T) {
	const extLen = 300
	value := make([]byte, extLen)
	for i := range value {
		value[i] = byte(i % 256)
	}
	// Type=2, Length=0xFF (sentinel), ExtendedLength=300 (big-endian), Value=300 bytes
	data := make([]byte, 0, ExtendedHeaderSize+extLen)
	data = append(data, 0x02, ExtendedLengthSentinel)
	data = binary.BigEndian.AppendUint16(data, extLen)
	data = append(data, value...)

	got, n, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if n != ExtendedHeaderSize+extLen {
		t.Fatalf("Parse: bytes consumed = %d, want %d", n, ExtendedHeaderSize+extLen)
	}
	if got.Type != 2 {
		t.Errorf("Type = %d, want 2", got.Type)
	}
	if got.Length != extLen {
		t.Errorf("Length = %d, want %d", got.Length, extLen)
	}
	if !bytes.Equal(got.Value, value) {
		t.Error("Value mismatch")
	}
}

func TestParseMultipleTLVs(t *testing.T) {
	// Two standard TLVs back to back.
	// TLV1: Type=10, Length=2, Value={0x01, 0x02}
	// TLV2: Type=20, Length=1, Value={0xff}
	data := []byte{
		10, 2, 0x01, 0x02,
		20, 1, 0xff,
	}
	tlvs, err := ParseAll(data)
	if err != nil {
		t.Fatalf("ParseAll: unexpected error: %v", err)
	}
	if len(tlvs) != 2 {
		t.Fatalf("ParseAll: got %d TLVs, want 2", len(tlvs))
	}
	if tlvs[0].Type != 10 || tlvs[0].Length != 2 {
		t.Errorf("TLV[0]: Type=%d Length=%d, want Type=10 Length=2", tlvs[0].Type, tlvs[0].Length)
	}
	if tlvs[1].Type != 20 || tlvs[1].Length != 1 {
		t.Errorf("TLV[1]: Type=%d Length=%d, want Type=20 Length=1", tlvs[1].Type, tlvs[1].Length)
	}
}

func TestMarshalStandard(t *testing.T) {
	tlv := TLV{
		Type:   1,
		Length: 3,
		Value:  []byte{0xaa, 0xbb, 0xcc},
	}
	got := tlv.Marshal()
	want := []byte{0x01, 0x03, 0xaa, 0xbb, 0xcc}
	if !bytes.Equal(got, want) {
		t.Errorf("Marshal() = %x, want %x", got, want)
	}
}

func TestMarshalExtended(t *testing.T) {
	value := make([]byte, 300)
	for i := range value {
		value[i] = byte(i % 256)
	}
	tlv := TLV{
		Type:   2,
		Length: 300,
		Value:  value,
	}
	got := tlv.Marshal()

	// Header: type=2, length sentinel=0xFF, extended length=300 big-endian
	if got[0] != 2 {
		t.Errorf("got[0] = %d, want 2", got[0])
	}
	if got[1] != ExtendedLengthSentinel {
		t.Errorf("got[1] = %d, want %d", got[1], ExtendedLengthSentinel)
	}
	extLen := binary.BigEndian.Uint16(got[2:4])
	if extLen != 300 {
		t.Errorf("extended length = %d, want 300", extLen)
	}
	if !bytes.Equal(got[4:], value) {
		t.Error("extended value mismatch")
	}
}

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input TLV
	}{
		{
			name:  "standard",
			input: TLV{Type: 5, Length: 4, Value: []byte{1, 2, 3, 4}},
		},
		{
			name:  "zero-length",
			input: TLV{Type: 7, Length: 0, Value: nil},
		},
		{
			name: "max-standard-length",
			input: TLV{
				Type:   9,
				Length: MaxStandardLength,
				Value:  bytes.Repeat([]byte{0xAB}, MaxStandardLength),
			},
		},
		{
			name: "min-extended-length",
			input: TLV{
				Type:   11,
				Length: MaxStandardLength + 1,
				Value:  bytes.Repeat([]byte{0xCD}, MaxStandardLength+1),
			},
		},
		{
			name: "extended-large",
			input: TLV{
				Type:   13,
				Length: 1000,
				Value:  bytes.Repeat([]byte{0xEF}, 1000),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := tt.input.Marshal()
			got, n, err := Parse(wire)
			if err != nil {
				t.Fatalf("Parse after Marshal: %v", err)
			}
			if n != len(wire) {
				t.Fatalf("bytes consumed = %d, want %d", n, len(wire))
			}
			if got.Type != tt.input.Type {
				t.Errorf("Type = %d, want %d", got.Type, tt.input.Type)
			}
			if got.Length != tt.input.Length {
				t.Errorf("Length = %d, want %d", got.Length, tt.input.Length)
			}
			if !bytes.Equal(got.Value, tt.input.Value) {
				t.Error("Value mismatch after round-trip")
			}
		})
	}
}

func TestRoundTripZeroLengthValue(t *testing.T) {
	// Zero-length TLV: Marshal should produce a nil Value on parse, but
	// we also accept empty slice. The key invariant is Length == 0.
	tlv := TLV{Type: 42, Length: 0, Value: []byte{}}
	wire := tlv.Marshal()
	got, _, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Length != 0 {
		t.Errorf("Length = %d, want 0", got.Length)
	}
	if len(got.Value) != 0 {
		t.Errorf("len(Value) = %d, want 0", len(got.Value))
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"type-only", []byte{0x01}},
		{"truncated-standard-value", []byte{0x01, 0x05, 0xaa}},
		{"extended-missing-ext-length", []byte{0x01, 0xff}},
		{"extended-partial-ext-length", []byte{0x01, 0xff, 0x00}},
		{"extended-truncated-value", []byte{0x01, 0xff, 0x01, 0x00, 0xaa}}, // claims 256 bytes, only 1
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Parse(tt.data)
			if err == nil {
				t.Error("Parse: expected error, got nil")
			}
		})
	}
}

func TestParseAllTrailingGarbage(t *testing.T) {
	// A valid TLV followed by a single stray byte should error on the second parse.
	data := []byte{0x01, 0x01, 0xaa, 0x02}
	_, err := ParseAll(data)
	if err == nil {
		t.Error("ParseAll: expected error for trailing garbage, got nil")
	}
}

func TestFindByType(t *testing.T) {
	tlvs := []TLV{
		{Type: 1, Length: 1, Value: []byte{0x11}},
		{Type: 2, Length: 1, Value: []byte{0x22}},
		{Type: 3, Length: 1, Value: []byte{0x33}},
	}

	got := FindByType(tlvs, 2)
	if got == nil {
		t.Fatal("FindByType(2): got nil, want non-nil")
	}
	if got.Type != 2 {
		t.Errorf("FindByType(2): Type = %d, want 2", got.Type)
	}
	if !bytes.Equal(got.Value, []byte{0x22}) {
		t.Errorf("FindByType(2): Value = %x, want 22", got.Value)
	}

	if FindByType(tlvs, 99) != nil {
		t.Error("FindByType(99): expected nil for missing type")
	}
}

func TestFindByTypeReturnsFirst(t *testing.T) {
	tlvs := []TLV{
		{Type: 5, Length: 1, Value: []byte{0x01}},
		{Type: 5, Length: 1, Value: []byte{0x02}},
	}
	got := FindByType(tlvs, 5)
	if got == nil {
		t.Fatal("FindByType: got nil")
	}
	if !bytes.Equal(got.Value, []byte{0x01}) {
		t.Errorf("FindByType returned second TLV instead of first: Value = %x", got.Value)
	}
}

func TestIsExtended(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"standard", []byte{0x01, 0x03, 0xaa, 0xbb, 0xcc}, false},
		{"extended", []byte{0x02, 0xff, 0x01, 0x00}, true},
		{"zero-length", []byte{0x03, 0x00}, false},
		{"max-standard", []byte{0x04, 0xfe}, false},
		{"too-short", []byte{0x01}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsExtended(tt.data); got != tt.want {
				t.Errorf("IsExtended(%x) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestZeroLengthTLV(t *testing.T) {
	data := []byte{0x05, 0x00}
	got, n, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if n != 2 {
		t.Fatalf("bytes consumed = %d, want 2", n)
	}
	if got.Type != 5 {
		t.Errorf("Type = %d, want 5", got.Type)
	}
	if got.Length != 0 {
		t.Errorf("Length = %d, want 0", got.Length)
	}
	if len(got.Value) != 0 {
		t.Errorf("len(Value) = %d, want 0", len(got.Value))
	}
}

func TestMaxStandardLengthTLV(t *testing.T) {
	value := bytes.Repeat([]byte{0xAA}, MaxStandardLength)
	data := make([]byte, 0, HeaderSize+MaxStandardLength)
	data = append(data, 0x06, MaxStandardLength)
	data = append(data, value...)

	got, n, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if n != HeaderSize+MaxStandardLength {
		t.Fatalf("bytes consumed = %d, want %d", n, HeaderSize+MaxStandardLength)
	}
	if got.Length != MaxStandardLength {
		t.Errorf("Length = %d, want %d", got.Length, MaxStandardLength)
	}
	if !bytes.Equal(got.Value, value) {
		t.Error("Value mismatch")
	}
}

func TestMinExtendedLengthTLV(t *testing.T) {
	// The minimum length that requires extended format is MaxStandardLength+1 = 255.
	const extLen = MaxStandardLength + 1
	value := bytes.Repeat([]byte{0xBB}, extLen)
	data := make([]byte, 0, ExtendedHeaderSize+extLen)
	data = append(data, 0x07, ExtendedLengthSentinel)
	data = binary.BigEndian.AppendUint16(data, extLen)
	data = append(data, value...)

	got, n, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if n != ExtendedHeaderSize+extLen {
		t.Fatalf("bytes consumed = %d, want %d", n, ExtendedHeaderSize+extLen)
	}
	if got.Length != extLen {
		t.Errorf("Length = %d, want %d", got.Length, extLen)
	}
	if !bytes.Equal(got.Value, value) {
		t.Error("Value mismatch")
	}
}

func TestMarshalAutoSelectsFormat(t *testing.T) {
	// Marshal with Length <= MaxStandardLength should produce standard format.
	std := TLV{Type: 1, Length: 10, Value: bytes.Repeat([]byte{0x01}, 10)}
	wire := std.Marshal()
	if wire[1] == ExtendedLengthSentinel {
		t.Error("Marshal: standard TLV should not use extended sentinel")
	}
	if len(wire) != HeaderSize+10 {
		t.Errorf("Marshal: len = %d, want %d", len(wire), HeaderSize+10)
	}

	// Marshal with Length > MaxStandardLength should produce extended format.
	ext := TLV{Type: 2, Length: 300, Value: bytes.Repeat([]byte{0x02}, 300)}
	wire = ext.Marshal()
	if wire[1] != ExtendedLengthSentinel {
		t.Error("Marshal: extended TLV should use extended sentinel")
	}
	if len(wire) != ExtendedHeaderSize+300 {
		t.Errorf("Marshal: len = %d, want %d", len(wire), ExtendedHeaderSize+300)
	}
}

func TestParseAllEmpty(t *testing.T) {
	tlvs, err := ParseAll(nil)
	if err != nil {
		t.Fatalf("ParseAll(nil): %v", err)
	}
	if len(tlvs) != 0 {
		t.Errorf("ParseAll(nil): got %d TLVs, want 0", len(tlvs))
	}

	tlvs, err = ParseAll([]byte{})
	if err != nil {
		t.Fatalf("ParseAll([]byte{}): %v", err)
	}
	if len(tlvs) != 0 {
		t.Errorf("ParseAll([]byte{}): got %d TLVs, want 0", len(tlvs))
	}
}

func TestMarshalUsesValueLengthNotField(t *testing.T) {
	// If Length field disagrees with len(Value), Marshal should use len(Value).
	tlv := TLV{Type: 1, Length: 999, Value: []byte{0x01, 0x02}}
	wire := tlv.Marshal()
	// Should be a standard TLV with length 2, not an extended TLV with length 999.
	if wire[1] == ExtendedLengthSentinel {
		t.Error("Marshal should derive length from len(Value), not the Length field")
	}
	parsed, _, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Length != 2 {
		t.Errorf("parsed Length = %d, want 2", parsed.Length)
	}
}

func FuzzParse(f *testing.F) {
	// Seed corpus with various formats.
	f.Add([]byte{0x01, 0x03, 0xaa, 0xbb, 0xcc})                         // standard
	f.Add([]byte{0x02, 0xff, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}) // extended
	f.Add([]byte{0x03, 0x00})                                           // zero-length
	f.Add([]byte{})                                                     // empty
	f.Add([]byte{0x01})                                                 // truncated

	f.Fuzz(func(_ *testing.T, data []byte) {
		// Must not panic.
		_, _, _ = Parse(data)
		_ = IsExtended(data)
		_, _ = ParseAll(data)
	})
}
