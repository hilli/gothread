// Package crc implements CRC-16 and CRC-32 checksum calculations
// as used in the OpenThread protocol stack.
//
// This is a pure Go port of the CRC computation from OpenThread's
// src/core/common/crc.hpp and crc.cpp. It provides CRC-16 (CCITT and ANSI)
// and CRC-32 (ANSI) using a bit-by-bit algorithm matching the original C++
// implementation.
package crc

// Standard CRC polynomials used by OpenThread.
const (
	// CRC16CCITTPolynomial is x^16 + x^12 + x^5 + 1.
	CRC16CCITTPolynomial uint16 = 0x1021

	// CRC16ANSIPolynomial is x^16 + x^15 + x^2 + 1.
	CRC16ANSIPolynomial uint16 = 0x8005

	// CRC32ANSIPolynomial is x^32 + x^26 + x^23 + x^22 + x^16 + x^12 +
	// x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1.
	CRC32ANSIPolynomial uint32 = 0x04c11db7
)

// CRC16 computes a 16-bit CRC using the given polynomial.
// The algorithm matches OpenThread's CrcCalculator<uint16_t>.
type CRC16 struct {
	polynomial uint16
	crc        uint16
}

// NewCRC16 returns a CRC16 calculator initialized with the given polynomial.
func NewCRC16(polynomial uint16) CRC16 {
	return CRC16{polynomial: polynomial}
}

// Reset sets the CRC accumulator back to zero.
func (c *CRC16) Reset() {
	c.crc = 0
}

// Update feeds a single byte into the CRC computation.
func (c *CRC16) Update(b byte) {
	c.crc ^= uint16(b) << 8

	for i := 0; i < 8; i++ {
		msbSet := c.crc&(1<<15) != 0
		c.crc <<= 1
		if msbSet {
			c.crc ^= c.polynomial
		}
	}
}

// Value returns the current CRC value.
func (c *CRC16) Value() uint16 {
	return c.crc
}

// CRC32 computes a 32-bit CRC using the given polynomial.
// The algorithm matches OpenThread's CrcCalculator<uint32_t>.
type CRC32 struct {
	polynomial uint32
	crc        uint32
}

// NewCRC32 returns a CRC32 calculator initialized with the given polynomial.
func NewCRC32(polynomial uint32) CRC32 {
	return CRC32{polynomial: polynomial}
}

// Reset sets the CRC accumulator back to zero.
func (c *CRC32) Reset() {
	c.crc = 0
}

// Update feeds a single byte into the CRC computation.
func (c *CRC32) Update(b byte) {
	c.crc ^= uint32(b) << 24

	for i := 0; i < 8; i++ {
		msbSet := c.crc&(1<<31) != 0
		c.crc <<= 1
		if msbSet {
			c.crc ^= c.polynomial
		}
	}
}

// Value returns the current CRC value.
func (c *CRC32) Value() uint32 {
	return c.crc
}

// ChecksumCRC16CCITT returns the CRC-16/CCITT checksum of data.
func ChecksumCRC16CCITT(data []byte) uint16 {
	c := NewCRC16(CRC16CCITTPolynomial)
	for _, b := range data {
		c.Update(b)
	}
	return c.Value()
}

// ChecksumCRC16ANSI returns the CRC-16/ANSI checksum of data.
func ChecksumCRC16ANSI(data []byte) uint16 {
	c := NewCRC16(CRC16ANSIPolynomial)
	for _, b := range data {
		c.Update(b)
	}
	return c.Value()
}

// ChecksumCRC32ANSI returns the CRC-32/ANSI checksum of data.
func ChecksumCRC32ANSI(data []byte) uint32 {
	c := NewCRC32(CRC32ANSIPolynomial)
	for _, b := range data {
		c.Update(b)
	}
	return c.Value()
}
