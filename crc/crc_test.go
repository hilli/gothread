package crc

import "testing"

// Test vectors from OpenThread: openthread/tests/unit/test_crc.cpp

func TestCRC16CCITT(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want uint16
	}{
		{"single 0xff", []byte{0xff}, 0x1ef0},
		{"123456789", []byte("123456789"), 0x31c3},
		{"mixed bytes", []byte{0x10, 0x20, 0x03, 0x15, 0xbe, 0xef, 0xca, 0xfe}, 0x926a},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test via Checksum convenience function.
			if got := ChecksumCRC16CCITT(tt.data); got != tt.want {
				t.Errorf("ChecksumCRC16CCITT() = 0x%04x, want 0x%04x", got, tt.want)
			}

			// Test via incremental Update interface.
			c := NewCRC16(CRC16CCITTPolynomial)
			for _, b := range tt.data {
				c.Update(b)
			}
			if got := c.Value(); got != tt.want {
				t.Errorf("CRC16.Value() = 0x%04x, want 0x%04x", got, tt.want)
			}
		})
	}
}

func TestCRC16ANSI(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want uint16
	}{
		{"single 0xff", []byte{0xff}, 0x0202},
		{"123456789", []byte("123456789"), 0xfee8},
		{"mixed bytes", []byte{0x10, 0x20, 0x03, 0x15, 0xbe, 0xef, 0xca, 0xfe}, 0x070c},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ChecksumCRC16ANSI(tt.data); got != tt.want {
				t.Errorf("ChecksumCRC16ANSI() = 0x%04x, want 0x%04x", got, tt.want)
			}

			c := NewCRC16(CRC16ANSIPolynomial)
			for _, b := range tt.data {
				c.Update(b)
			}
			if got := c.Value(); got != tt.want {
				t.Errorf("CRC16.Value() = 0x%04x, want 0x%04x", got, tt.want)
			}
		})
	}
}

func TestCRC32ANSI(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want uint32
	}{
		{"single 0xff", []byte{0xff}, 0xb1f740b4},
		{"123456789", []byte("123456789"), 0x89a1897f},
		{"mixed bytes", []byte{0x10, 0x20, 0x03, 0x15, 0xbe, 0xef, 0xca, 0xfe}, 0xd651e770},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ChecksumCRC32ANSI(tt.data); got != tt.want {
				t.Errorf("ChecksumCRC32ANSI() = 0x%08x, want 0x%08x", got, tt.want)
			}

			c := NewCRC32(CRC32ANSIPolynomial)
			for _, b := range tt.data {
				c.Update(b)
			}
			if got := c.Value(); got != tt.want {
				t.Errorf("CRC32.Value() = 0x%08x, want 0x%08x", got, tt.want)
			}
		})
	}
}

func TestCRC16Reset(t *testing.T) {
	c := NewCRC16(CRC16CCITTPolynomial)
	c.Update(0xff)
	c.Reset()
	if got := c.Value(); got != 0 {
		t.Errorf("after Reset(), Value() = 0x%04x, want 0x0000", got)
	}

	// Feeding data after reset should produce the correct CRC.
	for _, b := range []byte("123456789") {
		c.Update(b)
	}
	if got := c.Value(); got != 0x31c3 {
		t.Errorf("after Reset() + feed, Value() = 0x%04x, want 0x31c3", got)
	}
}

func TestCRC32Reset(t *testing.T) {
	c := NewCRC32(CRC32ANSIPolynomial)
	c.Update(0xff)
	c.Reset()
	if got := c.Value(); got != 0 {
		t.Errorf("after Reset(), Value() = 0x%08x, want 0x00000000", got)
	}
}

func TestEmptyInput(t *testing.T) {
	if got := ChecksumCRC16CCITT(nil); got != 0 {
		t.Errorf("CRC16 CCITT of empty input = 0x%04x, want 0x0000", got)
	}
	if got := ChecksumCRC16ANSI(nil); got != 0 {
		t.Errorf("CRC16 ANSI of empty input = 0x%04x, want 0x0000", got)
	}
	if got := ChecksumCRC32ANSI(nil); got != 0 {
		t.Errorf("CRC32 ANSI of empty input = 0x%08x, want 0x00000000", got)
	}
}

func FuzzCRC16CCITT(f *testing.F) {
	f.Add([]byte{0xff})
	f.Add([]byte("123456789"))
	f.Add([]byte{0x10, 0x20, 0x03, 0x15, 0xbe, 0xef, 0xca, 0xfe})
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, data []byte) {
		// Must not panic on any input.
		_ = ChecksumCRC16CCITT(data)
	})
}
