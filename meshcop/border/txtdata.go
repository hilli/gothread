// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package border

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	goterrors "github.com/hilli/gothread/errors"
)

// Thread-defined mDNS TXT record keys for Border Agent service discovery.
const (
	// TxtKeyNetworkName is the network name key ("nn").
	TxtKeyNetworkName = "nn"
	// TxtKeyExtPanID is the extended PAN ID key ("xp").
	TxtKeyExtPanID = "xp"
	// TxtKeyThreadVersion is the Thread version key ("tv").
	TxtKeyThreadVersion = "tv"
	// TxtKeyDiscriminator is the discriminator key ("dd").
	TxtKeyDiscriminator = "dd"
	// TxtKeyActiveTimestamp is the active timestamp key ("at").
	TxtKeyActiveTimestamp = "at"
	// TxtKeyPartitionID is the partition ID key ("pt").
	TxtKeyPartitionID = "pt"
	// TxtKeySequenceNumber is the sequence number key ("sq").
	TxtKeySequenceNumber = "sq"
	// TxtKeyStateBitmap is the state bitmap key ("sb").
	TxtKeyStateBitmap = "sb"
	// TxtKeyVendorName is the vendor name key ("vn").
	TxtKeyVendorName = "vn"
	// TxtKeyModelName is the model name key ("mn").
	TxtKeyModelName = "mn"
	// TxtKeyBorderAgentID is the border agent ID key ("id").
	TxtKeyBorderAgentID = "id"
)

// TxtEntry represents a single DNS-SD TXT record key-value pair.
type TxtEntry struct {
	Key   string
	Value []byte
}

// TxtData holds Border Agent mDNS TXT record key-value pairs for
// service advertisement and discovery.
type TxtData struct {
	entries []TxtEntry
}

// NewTxtData creates an empty TxtData.
func NewTxtData() *TxtData {
	return &TxtData{}
}

// Set sets or replaces a TXT record entry.
func (td *TxtData) Set(key string, value []byte) {
	for i := range td.entries {
		if td.entries[i].Key == key {
			td.entries[i].Value = copyBytes(value)
			return
		}
	}
	td.entries = append(td.entries, TxtEntry{Key: key, Value: copyBytes(value)})
}

// Get returns the value for the given key, or nil if not found.
func (td *TxtData) Get(key string) []byte {
	for _, e := range td.entries {
		if e.Key == key {
			return e.Value
		}
	}
	return nil
}

// Has reports whether the given key is present.
func (td *TxtData) Has(key string) bool {
	for _, e := range td.entries {
		if e.Key == key {
			return true
		}
	}
	return false
}

// Remove removes the entry with the given key.
func (td *TxtData) Remove(key string) {
	for i, e := range td.entries {
		if e.Key == key {
			td.entries = append(td.entries[:i], td.entries[i+1:]...)
			return
		}
	}
}

// Entries returns a copy of all entries.
func (td *TxtData) Entries() []TxtEntry {
	result := make([]TxtEntry, len(td.entries))
	for i, e := range td.entries {
		result[i] = TxtEntry{Key: e.Key, Value: copyBytes(e.Value)}
	}
	return result
}

// Encode serializes all entries into DNS-SD TXT record format.
// Each entry is encoded as: len(1 byte) + "key=value".
// Returns the encoded bytes.
func (td *TxtData) Encode() []byte {
	var buf []byte
	for _, e := range td.entries {
		var entry []byte
		if e.Value != nil {
			entry = []byte(e.Key + "=")
			entry = append(entry, e.Value...)
		} else {
			entry = []byte(e.Key)
		}
		if len(entry) > 255 {
			// Truncate to max DNS-SD TXT entry length.
			entry = entry[:255]
		}
		buf = append(buf, byte(len(entry)))
		buf = append(buf, entry...)
	}
	return buf
}

// Decode parses DNS-SD TXT record format data into entries.
// Each entry is: len(1 byte) + "key=value" or "key" (boolean).
func (td *TxtData) Decode(data []byte) error {
	td.entries = nil
	offset := 0

	for offset < len(data) {
		if offset >= len(data) {
			break
		}
		entryLen := int(data[offset])
		offset++

		if offset+entryLen > len(data) {
			return goterrors.ErrParse
		}

		entry := data[offset : offset+entryLen]
		offset += entryLen

		// Split on first '='.
		eqIdx := -1
		for i, b := range entry {
			if b == '=' {
				eqIdx = i
				break
			}
		}

		if eqIdx < 0 {
			// Boolean key (no value).
			td.entries = append(td.entries, TxtEntry{
				Key:   string(entry),
				Value: nil,
			})
		} else {
			td.entries = append(td.entries, TxtEntry{
				Key:   string(entry[:eqIdx]),
				Value: copyBytes(entry[eqIdx+1:]),
			})
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Typed getters and setters for Thread-defined keys
// ---------------------------------------------------------------------------

// SetNetworkName sets the "nn" (network name) field.
func (td *TxtData) SetNetworkName(name string) {
	td.Set(TxtKeyNetworkName, []byte(name))
}

// GetNetworkName returns the network name, or empty string if not set.
func (td *TxtData) GetNetworkName() string {
	v := td.Get(TxtKeyNetworkName)
	if v == nil {
		return ""
	}
	return string(v)
}

// SetExtPanID sets the "xp" (extended PAN ID) field as a 16-char hex string.
func (td *TxtData) SetExtPanID(id [8]byte) {
	td.Set(TxtKeyExtPanID, []byte(hex.EncodeToString(id[:])))
}

// GetExtPanID returns the extended PAN ID, or a zero value if not set or invalid.
func (td *TxtData) GetExtPanID() [8]byte {
	var id [8]byte
	v := td.Get(TxtKeyExtPanID)
	if v == nil || len(v) != 16 {
		return id
	}
	decoded, err := hex.DecodeString(string(v))
	if err != nil || len(decoded) != 8 {
		return id
	}
	copy(id[:], decoded)
	return id
}

// SetThreadVersion sets the "tv" (Thread version) field.
func (td *TxtData) SetThreadVersion(version string) {
	td.Set(TxtKeyThreadVersion, []byte(version))
}

// GetThreadVersion returns the Thread version string.
func (td *TxtData) GetThreadVersion() string {
	v := td.Get(TxtKeyThreadVersion)
	if v == nil {
		return ""
	}
	return string(v)
}

// SetDiscriminator sets the "dd" (discriminator) field as a hex-encoded value.
func (td *TxtData) SetDiscriminator(disc []byte) {
	td.Set(TxtKeyDiscriminator, []byte(hex.EncodeToString(disc)))
}

// GetDiscriminator returns the discriminator as raw bytes, or nil if not set.
func (td *TxtData) GetDiscriminator() []byte {
	v := td.Get(TxtKeyDiscriminator)
	if v == nil {
		return nil
	}
	decoded, err := hex.DecodeString(string(v))
	if err != nil {
		return nil
	}
	return decoded
}

// SetActiveTimestamp sets the "at" (active timestamp) field as a hex string.
func (td *TxtData) SetActiveTimestamp(ts uint64) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, ts)
	td.Set(TxtKeyActiveTimestamp, []byte(hex.EncodeToString(buf)))
}

// GetActiveTimestamp returns the active timestamp, or 0 if not set or invalid.
func (td *TxtData) GetActiveTimestamp() uint64 {
	v := td.Get(TxtKeyActiveTimestamp)
	if v == nil {
		return 0
	}
	decoded, err := hex.DecodeString(string(v))
	if err != nil || len(decoded) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(decoded)
}

// SetPartitionID sets the "pt" (partition ID) field.
func (td *TxtData) SetPartitionID(id uint32) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, id)
	td.Set(TxtKeyPartitionID, []byte(fmt.Sprintf("%08x", id)))
}

// GetPartitionID returns the partition ID, or 0 if not set.
func (td *TxtData) GetPartitionID() uint32 {
	v := td.Get(TxtKeyPartitionID)
	if v == nil {
		return 0
	}
	decoded, err := hex.DecodeString(string(v))
	if err != nil || len(decoded) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(decoded)
}

// SetSequenceNumber sets the "sq" (sequence number) field.
func (td *TxtData) SetSequenceNumber(seq uint8) {
	td.Set(TxtKeySequenceNumber, []byte(fmt.Sprintf("%02x", seq)))
}

// GetSequenceNumber returns the sequence number, or 0 if not set.
func (td *TxtData) GetSequenceNumber() uint8 {
	v := td.Get(TxtKeySequenceNumber)
	if v == nil || len(v) != 2 {
		return 0
	}
	decoded, err := hex.DecodeString(string(v))
	if err != nil || len(decoded) != 1 {
		return 0
	}
	return decoded[0]
}

// SetStateBitmap sets the "sb" (state bitmap) field.
func (td *TxtData) SetStateBitmap(bitmap uint32) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, bitmap)
	td.Set(TxtKeyStateBitmap, []byte(hex.EncodeToString(buf)))
}

// GetStateBitmap returns the state bitmap, or 0 if not set.
func (td *TxtData) GetStateBitmap() uint32 {
	v := td.Get(TxtKeyStateBitmap)
	if v == nil {
		return 0
	}
	decoded, err := hex.DecodeString(string(v))
	if err != nil || len(decoded) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(decoded)
}

// SetVendorName sets the "vn" (vendor name) field.
func (td *TxtData) SetVendorName(name string) {
	td.Set(TxtKeyVendorName, []byte(name))
}

// GetVendorName returns the vendor name.
func (td *TxtData) GetVendorName() string {
	v := td.Get(TxtKeyVendorName)
	if v == nil {
		return ""
	}
	return string(v)
}

// SetModelName sets the "mn" (model name) field.
func (td *TxtData) SetModelName(name string) {
	td.Set(TxtKeyModelName, []byte(name))
}

// GetModelName returns the model name.
func (td *TxtData) GetModelName() string {
	v := td.Get(TxtKeyModelName)
	if v == nil {
		return ""
	}
	return string(v)
}

// SetBorderAgentID sets the "id" (border agent ID) field as hex.
func (td *TxtData) SetBorderAgentID(id []byte) {
	td.Set(TxtKeyBorderAgentID, []byte(hex.EncodeToString(id)))
}

// GetBorderAgentID returns the border agent ID as raw bytes, or nil.
func (td *TxtData) GetBorderAgentID() []byte {
	v := td.Get(TxtKeyBorderAgentID)
	if v == nil {
		return nil
	}
	decoded, err := hex.DecodeString(string(v))
	if err != nil {
		return nil
	}
	return decoded
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// copyBytes returns a copy of a byte slice.
func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
