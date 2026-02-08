// Package checksum implements Internet checksum (RFC 1071) and Verhoeff
// checksum algorithms.
//
// The Internet checksum is the one's complement sum used in IP, UDP, TCP,
// and ICMP headers. The implementation supports incremental computation,
// matching the approach in OpenThread's checksum.hpp.
//
// Reference: openthread/src/core/net/checksum.hpp
// Reference: openthread/src/core/net/checksum.cpp
package checksum

// Checksum implements incremental Internet checksum (RFC 1071) computation.
//
// The zero value is ready to use. Feed data with [Checksum.AddUint8],
// [Checksum.AddUint16], or [Checksum.AddData], then read the accumulated
// one's complement sum with [Checksum.Value] or the final checksum with
// [Checksum.Finalize].
type Checksum struct {
	value      uint16
	atOddIndex bool
}

// Value returns the current accumulated one's complement sum.
//
// When verifying a received message that already contains a valid checksum,
// the value should be 0xffff.
func (c *Checksum) Value() uint16 {
	return c.value
}

// AddUint8 feeds a single byte into the checksum in big-endian order.
// Even-indexed bytes occupy the high 8 bits; odd-indexed bytes occupy
// the low 8 bits of each 16-bit word.
func (c *Checksum) AddUint8(b uint8) {
	var add uint16
	if c.atOddIndex {
		add = uint16(b)
	} else {
		add = uint16(b) << 8
	}

	newValue := uint32(c.value) + uint32(add)

	// Fold the carry bit back into the 16-bit sum (one's complement add).
	if newValue > 0xffff {
		newValue = (newValue & 0xffff) + 1
	}

	c.value = uint16(newValue)
	c.atOddIndex = !c.atOddIndex
}

// AddUint16 feeds a 16-bit value into the checksum in big-endian byte order.
func (c *Checksum) AddUint16(v uint16) {
	c.AddUint8(uint8(v >> 8))
	c.AddUint8(uint8(v))
}

// AddData feeds a byte slice into the checksum.
func (c *Checksum) AddData(data []byte) {
	for _, b := range data {
		c.AddUint8(b)
	}
}

// Finalize returns the final Internet checksum: the one's complement (bitwise
// NOT) of the accumulated sum. This is the value written into protocol headers.
//
// Per RFC 1071, if the accumulated sum is 0xffff the checksum is returned
// as 0xffff (not 0x0000), since 0x0000 is reserved to mean "no checksum"
// in some protocols (e.g., UDP over IPv4).
func (c *Checksum) Finalize() uint16 {
	if c.value == 0xffff {
		return 0xffff
	}
	return ^c.value
}
