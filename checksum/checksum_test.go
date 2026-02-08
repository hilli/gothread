package checksum

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestInternetChecksumRFC1071Vector verifies the example from RFC 1071.
func TestInternetChecksumRFC1071Vector(t *testing.T) {
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	want := uint16(0xddf2)

	var c Checksum
	c.AddData(data)
	got := c.Value()

	if got != want {
		t.Errorf("Checksum.Value() = 0x%04x, want 0x%04x", got, want)
	}
}

// TestInternetChecksumInitialValue verifies that a new Checksum starts at zero.
func TestInternetChecksumInitialValue(t *testing.T) {
	var c Checksum
	if c.Value() != 0 {
		t.Errorf("initial value = 0x%04x, want 0x0000", c.Value())
	}
}

// TestInternetChecksumICMP4Echo verifies the checksum of a captured ICMP4
// echo request message. The checksum field in the message is zeroed before
// calculation; the expected result is the one's complement of the accumulated
// value. This matches TestIcmp4MessageChecksum in the C++ test suite.
func TestInternetChecksumICMP4Echo(t *testing.T) {
	// Captured ICMP echo request (64 bytes). The checksum field (bytes 2-3)
	// is zeroed out, matching the C++ test vector.
	raw, err := hex.DecodeString(
		"08000000" + "672e0000" + "62aff161" + "0004fc24" +
			"08090a0b" + "0c0d0e0f" + "10111213" + "14151617" +
			"18191a1b" + "1c1d1e1f" + "20212223" + "24252627" +
			"28292a2b" + "2c2d2e2f" + "30313233" + "34353637")
	if err != nil {
		t.Fatal(err)
	}

	want := uint16(0x5594)

	var c Checksum
	c.AddData(raw)

	// The ICMP checksum is the one's complement of the accumulated value.
	got := c.Finalize()
	if got != want {
		t.Errorf("ICMP4 echo checksum = 0x%04x, want 0x%04x", got, want)
	}
}

// TestInternetChecksumFinalizeAndVerify checks that feeding data that already
// includes a valid checksum produces the expected 0xffff verification value.
func TestInternetChecksumFinalizeAndVerify(t *testing.T) {
	// Build the ICMP message with the correct checksum inserted.
	raw, _ := hex.DecodeString(
		"08005594" + "672e0000" + "62aff161" + "0004fc24" +
			"08090a0b" + "0c0d0e0f" + "10111213" + "14151617" +
			"18191a1b" + "1c1d1e1f" + "20212223" + "24252627" +
			"28292a2b" + "2c2d2e2f" + "30313233" + "34353637")

	var c Checksum
	c.AddData(raw)
	if c.Value() != 0xffff {
		t.Errorf("verification checksum = 0x%04x, want 0xffff", c.Value())
	}
}

// TestInternetChecksumIncrementalEquivalence verifies that feeding data byte
// by byte produces the same result as feeding it all at once.
func TestInternetChecksumIncrementalEquivalence(t *testing.T) {
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}

	var whole Checksum
	whole.AddData(data)

	var incr Checksum
	for _, b := range data {
		incr.AddUint8(b)
	}

	if whole.Value() != incr.Value() {
		t.Errorf("incremental 0x%04x != whole 0x%04x", incr.Value(), whole.Value())
	}
}

// TestInternetChecksumAddUint16 verifies AddUint16 in big-endian order.
func TestInternetChecksumAddUint16(t *testing.T) {
	// Feeding 0x0001 as a uint16 should be the same as feeding 0x00, 0x01.
	var a Checksum
	a.AddUint16(0x0001)

	var b Checksum
	b.AddUint8(0x00)
	b.AddUint8(0x01)

	if a.Value() != b.Value() {
		t.Errorf("AddUint16 0x%04x != AddUint8 pair 0x%04x", a.Value(), b.Value())
	}
}

// TestInternetChecksumOddLength verifies correct handling of odd-length data.
func TestInternetChecksumOddLength(t *testing.T) {
	data := []byte{0x45, 0x00, 0x00, 0x73, 0x00}
	var c Checksum
	c.AddData(data)

	// Manually: 0x4500 + 0x0073 + 0x0000 (padded) = 0x4573
	// One's complement: no overflow, so value is 0x4573.
	if c.Value() != 0x4573 {
		t.Errorf("odd-length checksum = 0x%04x, want 0x4573", c.Value())
	}
}

// TestInternetChecksumEmpty verifies empty data produces zero.
func TestInternetChecksumEmpty(t *testing.T) {
	var c Checksum
	c.AddData(nil)
	if c.Value() != 0 {
		t.Errorf("empty checksum = 0x%04x, want 0x0000", c.Value())
	}
}

// FuzzInternetChecksum tests that the checksum of data with a valid checksum
// appended always verifies to 0xffff (the property of RFC 1071).
func FuzzInternetChecksum(f *testing.F) {
	f.Add([]byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7})
	f.Add([]byte{0xff, 0xff})
	f.Add([]byte{0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		// Compute checksum of the data.
		var c Checksum
		c.AddData(data)
		csum := c.Finalize()

		// Append the checksum (big-endian) and verify.
		withChecksum := make([]byte, len(data)+2)
		copy(withChecksum, data)
		withChecksum[len(data)] = byte(csum >> 8)
		withChecksum[len(data)+1] = byte(csum)

		var v Checksum
		v.AddData(withChecksum)
		if v.Value() != 0xffff {
			t.Errorf("data %x: checksum 0x%04x did not verify (got 0x%04x)",
				data, csum, v.Value())
		}
	})
}

// --- Verhoeff checksum tests ---

// TestVerhoeffValidate checks the known valid strings from the C++ test suite.
func TestVerhoeffValidate(t *testing.T) {
	valid := []string{
		"307318421",
		"487300178",
		"123455672",
		"0",
		"15",
		"999999994",
		"000000001",
		"100000000",
		"2363",
	}

	for _, s := range valid {
		if !VerhoeffValidate(s) {
			t.Errorf("VerhoeffValidate(%q) = false, want true", s)
		}
	}
}

// TestVerhoeffCalculate verifies that Calculate produces the correct check
// digit for each test vector.
func TestVerhoeffCalculate(t *testing.T) {
	cases := []struct {
		input     string // digits without check digit
		wantDigit byte   // expected check digit character
	}{
		{"30731842", '1'},
		{"48730017", '8'},
		{"12345567", '2'},
		{"", '0'},  // "0" is valid, so Calculate("") -> '0'
		{"1", '5'}, // "15" is valid
		{"99999999", '4'},
		{"00000000", '1'},
		{"10000000", '0'},
		{"236", '3'},
	}

	for _, tc := range cases {
		got, err := VerhoeffCalculate(tc.input)
		if err != nil {
			t.Errorf("VerhoeffCalculate(%q) error: %v", tc.input, err)
			continue
		}
		if got != tc.wantDigit {
			t.Errorf("VerhoeffCalculate(%q) = %q, want %q", tc.input, got, tc.wantDigit)
		}
	}
}

// TestVerhoeffInvalidChecksum verifies that altering the check digit makes
// validation fail.
func TestVerhoeffInvalidChecksum(t *testing.T) {
	valid := "307318421"
	// Change last digit
	invalid := valid[:len(valid)-1] + "0" // was '1', now '0'
	if VerhoeffValidate(invalid) {
		t.Errorf("VerhoeffValidate(%q) = true, want false", invalid)
	}
}

// TestVerhoeffInvalidFormat verifies that non-digit strings are rejected.
func TestVerhoeffInvalidFormat(t *testing.T) {
	invalid := []string{
		"307 318421",
		"307318421 ",
		" 307318421",
		"ABCDE",
	}

	for _, s := range invalid {
		if VerhoeffValidate(s) {
			t.Errorf("VerhoeffValidate(%q) = true, want false", s)
		}
		_, err := VerhoeffCalculate(s)
		if err == nil {
			t.Errorf("VerhoeffCalculate(%q) returned nil error, want error", s)
		}
	}
}

// TestVerhoeffRoundTrip verifies that Calculate followed by Validate is
// consistent for a variety of inputs.
func TestVerhoeffRoundTrip(t *testing.T) {
	inputs := []string{
		"0", "1", "12345", "99999999", "00000000",
		"11111111", "987654321",
	}

	for _, s := range inputs {
		digit, err := VerhoeffCalculate(s)
		if err != nil {
			t.Errorf("VerhoeffCalculate(%q) error: %v", s, err)
			continue
		}
		full := s + string(digit)
		if !VerhoeffValidate(full) {
			t.Errorf("VerhoeffValidate(%q) = false after Calculate", full)
		}
	}
}

// TestVerhoeffDetectsAllSingleDigitErrors verifies that changing any single
// digit in a valid string is detected.
func TestVerhoeffDetectsAllSingleDigitErrors(t *testing.T) {
	valid := "307318421"

	for i := 0; i < len(valid); i++ {
		for d := byte('0'); d <= '9'; d++ {
			if d == valid[i] {
				continue
			}
			corrupted := valid[:i] + string(d) + valid[i+1:]
			if VerhoeffValidate(corrupted) {
				t.Errorf("single-digit change at %d (%q) not detected", i, corrupted)
			}
		}
	}
}

// TestVerhoeffDetectsAdjacentTranspositions verifies that swapping any two
// adjacent digits in a valid string is detected.
func TestVerhoeffDetectsAdjacentTranspositions(t *testing.T) {
	valid := "307318421"

	for i := 0; i < len(valid)-1; i++ {
		if valid[i] == valid[i+1] {
			continue // transposing identical digits is not a change
		}
		transposed := valid[:i] + string(valid[i+1]) + string(valid[i]) + valid[i+2:]
		if VerhoeffValidate(transposed) {
			t.Errorf("adjacent transposition at %d (%q) not detected", i, transposed)
		}
	}
}

// TestVerhoeffCalculateEmptyIsZero verifies that the check digit for an
// empty string is '0'.
func TestVerhoeffCalculateEmptyIsZero(t *testing.T) {
	got, err := VerhoeffCalculate("")
	if err != nil {
		t.Fatalf("VerhoeffCalculate(%q) error: %v", "", err)
	}
	if got != '0' {
		t.Errorf("VerhoeffCalculate(%q) = %q, want '0'", "", got)
	}
}

// TestVerhoeffLongString verifies that strings up to the maximum length work.
func TestVerhoeffLongString(t *testing.T) {
	// MaxStringLength from the C++ code is quite generous. Test with a
	// moderately long string.
	s := strings.Repeat("1", 100)
	digit, err := VerhoeffCalculate(s)
	if err != nil {
		t.Fatalf("VerhoeffCalculate(100 ones) error: %v", err)
	}
	full := s + string(digit)
	if !VerhoeffValidate(full) {
		t.Errorf("VerhoeffValidate failed for 100-ones + check digit")
	}
}
