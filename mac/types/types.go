// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package types defines the MAC-layer address and key types used
// throughout gothread.
//
// This is a Go port of the types in OpenThread's
// src/core/mac/mac_types.hpp and src/core/mac/mac_types.cpp.
package types //nolint:revive // short package name is intentional for mac/types

import "fmt"

// ---------------- ByteOrder ------------------------------------------------

// ByteOrder specifies the byte order used when copying an ExtAddress.
type ByteOrder uint8

const (
	// NormalByteOrder copies bytes as-is.
	NormalByteOrder ByteOrder = iota
	// ReverseByteOrder copies bytes in reverse order.
	ReverseByteOrder
)

// ---------------- ExtAddress -----------------------------------------------

// ExtAddressSize is the length in bytes of an IEEE 802.15.4 Extended Address.
const ExtAddressSize = 8

// ExtAddress represents an IEEE 802.15.4 Extended Address (8 bytes).
type ExtAddress [ExtAddressSize]byte

const (
	groupFlag = 1 << 0 // bit 0 of byte 0
	localFlag = 1 << 1 // bit 1 of byte 0
)

// IsGroup reports whether the Group bit (bit 0 of byte 0) is set.
func (a *ExtAddress) IsGroup() bool { return (a[0] & groupFlag) != 0 }

// SetGroup sets or clears the Group bit.
func (a *ExtAddress) SetGroup(group bool) {
	if group {
		a[0] |= groupFlag
	} else {
		a[0] &^= groupFlag
	}
}

// ToggleGroup flips the Group bit.
func (a *ExtAddress) ToggleGroup() { a[0] ^= groupFlag }

// IsLocal reports whether the Local bit (bit 1 of byte 0) is set.
func (a *ExtAddress) IsLocal() bool { return (a[0] & localFlag) != 0 }

// SetLocal sets or clears the Local bit.
func (a *ExtAddress) SetLocal(local bool) {
	if local {
		a[0] |= localFlag
	} else {
		a[0] &^= localFlag
	}
}

// ToggleLocal flips the Local bit.
func (a *ExtAddress) ToggleLocal() { a[0] ^= localFlag }

// CopyTo copies the Extended Address into dst using the given byte order.
// dst must be at least ExtAddressSize bytes.
func (a *ExtAddress) CopyTo(dst []byte, order ByteOrder) {
	switch order {
	case ReverseByteOrder:
		for i := range ExtAddressSize {
			dst[i] = a[ExtAddressSize-1-i]
		}
	default: // NormalByteOrder
		copy(dst, a[:])
	}
}

// Set sets the Extended Address from src using the given byte order.
// src must be at least ExtAddressSize bytes.
func (a *ExtAddress) Set(src []byte, order ByteOrder) {
	switch order {
	case ReverseByteOrder:
		for i := range ExtAddressSize {
			a[i] = src[ExtAddressSize-1-i]
		}
	default:
		copy(a[:], src)
	}
}

// ToString returns the address as a 16-char lowercase hex string with no
// separators (e.g. "aabbccddeeff0011").
func (a ExtAddress) ToString() string {
	return fmt.Sprintf("%02x%02x%02x%02x%02x%02x%02x%02x",
		a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7])
}

// ---------------- ShortAddress ---------------------------------------------

// ShortAddress represents an IEEE 802.15.4 Short Address.
type ShortAddress uint16

const (
	// BroadcastAddress is the broadcast short address (0xffff).
	BroadcastAddress ShortAddress = 0xffff
	// ShortAddressInvalid is the invalid short address (0xfffe).
	ShortAddressInvalid ShortAddress = 0xfffe
)

// ToString returns the short address formatted as "0x%04x".
func (s ShortAddress) ToString() string {
	return fmt.Sprintf("0x%04x", uint16(s))
}

// ---------------- PanId ----------------------------------------------------

// PanID represents an IEEE 802.15.4 PAN ID.
type PanID uint16

const (
	// BroadcastPanID is the broadcast PAN ID (0xffff).
	BroadcastPanID PanID = 0xffff
)

// ---------------- Address (tagged union) -----------------------------------

// AddressType identifies the kind of address in an Address.
type AddressType uint8

const (
	// AddressTypeNone indicates no address.
	AddressTypeNone AddressType = iota
	// AddressTypeShort indicates an IEEE 802.15.4 Short Address.
	AddressTypeShort
	// AddressTypeExtended indicates an IEEE 802.15.4 Extended Address.
	AddressTypeExtended
)

// Address represents an IEEE 802.15.4 Short or Extended Address (tagged
// union). The zero value is an address of type None.
type Address struct {
	typ      AddressType
	short    ShortAddress
	extended ExtAddress
}

// GetType returns the address type.
func (a *Address) GetType() AddressType { return a.typ }

// IsNone reports whether the address type is None.
func (a *Address) IsNone() bool { return a.typ == AddressTypeNone }

// IsShort reports whether the address is a Short Address.
func (a *Address) IsShort() bool { return a.typ == AddressTypeShort }

// IsExtended reports whether the address is an Extended Address.
func (a *Address) IsExtended() bool { return a.typ == AddressTypeExtended }

// GetShort returns the Short Address. Must only be called when IsShort is true.
func (a *Address) GetShort() ShortAddress { return a.short }

// GetExtended returns the Extended Address. Must only be called when
// IsExtended is true.
func (a *Address) GetExtended() ExtAddress { return a.extended }

// SetNone clears the address (sets type to None).
func (a *Address) SetNone() { a.typ = AddressTypeNone }

// SetShort sets the address to a Short Address.
func (a *Address) SetShort(s ShortAddress) {
	a.short = s
	a.typ = AddressTypeShort
}

// SetExtended sets the address to an Extended Address.
func (a *Address) SetExtended(e ExtAddress) {
	a.extended = e
	a.typ = AddressTypeExtended
}

// IsBroadcast reports whether the address is the short broadcast address
// (0xffff).
func (a *Address) IsBroadcast() bool {
	return a.typ == AddressTypeShort && a.short == BroadcastAddress
}

// IsShortAddrInvalid reports whether the address is the short invalid
// address (0xfffe).
func (a *Address) IsShortAddrInvalid() bool {
	return a.typ == AddressTypeShort && a.short == ShortAddressInvalid
}

// ToString returns a human-readable string for the address.
func (a *Address) ToString() string {
	switch a.typ {
	case AddressTypeExtended:
		return a.extended.ToString()
	case AddressTypeShort:
		return a.short.ToString()
	default:
		return "None"
	}
}

// Equal reports whether two Address values are equal.
func (a *Address) Equal(other *Address) bool {
	if a.typ != other.typ {
		return false
	}
	switch a.typ {
	case AddressTypeNone:
		return true
	case AddressTypeShort:
		return a.short == other.short
	case AddressTypeExtended:
		return a.extended == other.extended
	default:
		return false
	}
}

// ---------------- Key ------------------------------------------------------

// KeySize is the length in bytes of a MAC key.
const KeySize = 16

// Key represents a 128-bit MAC key.
type Key [KeySize]byte

// ---------------- KeyMaterial ----------------------------------------------

// KeyMaterial wraps a Key for platform abstraction. In this pure-Go
// implementation there is no key reference indirection.
type KeyMaterial struct {
	key Key
}

// GetKey returns the contained Key.
func (km *KeyMaterial) GetKey() Key { return km.key }

// SetKey sets the contained Key.
func (km *KeyMaterial) SetKey(k Key) { km.key = k }

// Clear zeroes the contained key.
func (km *KeyMaterial) Clear() { km.key = Key{} }
