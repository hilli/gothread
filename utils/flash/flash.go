// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package flash implements a dual-swap wear-leveling flash storage.
//
// Records are stored sequentially in the active swap region. Each record
// consists of a 2-byte key, 2-byte length, N-byte value, and 2-byte CRC16.
// When the active swap fills up, valid records are compacted into the
// inactive swap, which then becomes the active swap.
//
// This is a Go port of OpenThread's src/core/utils/flash.cpp.
package flash

import (
	"encoding/binary"

	"github.com/hilli/gothread/errors"
)

// SwapSize is the default size of each swap region in bytes.
const SwapSize = 2048

// recordHeaderSize is the size of a record header (key + length) in bytes.
const recordHeaderSize = 4

// recordCRCSize is the size of the CRC16 trailer in bytes.
const recordCRCSize = 2

// recordOverhead is the total overhead per record (header + CRC).
const recordOverhead = recordHeaderSize + recordCRCSize

// deletedKey is the sentinel key value marking a deleted record.
const deletedKey = 0xFFFF

// Flash provides a dual-swap wear-leveling flash storage.
type Flash struct {
	swaps     [2][]byte
	swapIndex int
	swapUsed  int
	swapSize  int
}

// Init initialises the flash storage with the given swap region size.
// If swapSize is zero, SwapSize is used.
func (f *Flash) Init(swapSize int) error {
	if swapSize <= 0 {
		swapSize = SwapSize
	}
	if swapSize < recordOverhead {
		return errors.ErrInvalidArgs
	}
	f.swapSize = swapSize
	f.swaps[0] = make([]byte, swapSize)
	f.swaps[1] = make([]byte, swapSize)
	f.swapIndex = 0
	f.swapUsed = 0
	return nil
}

// Wipe erases all data from both swap regions.
func (f *Flash) Wipe() {
	for i := range f.swaps {
		for j := range f.swaps[i] {
			f.swaps[i][j] = 0
		}
	}
	f.swapIndex = 0
	f.swapUsed = 0
}

// Add appends a record with the given key and value to the active swap.
func (f *Flash) Add(key uint16, value []byte) error {
	if key == deletedKey {
		return errors.ErrInvalidArgs
	}
	recSize := recordOverhead + len(value)
	if recSize > f.swapSize {
		return errors.ErrNoBufs
	}
	if f.swapUsed+recSize > f.swapSize {
		if err := f.compact(); err != nil {
			return err
		}
		if f.swapUsed+recSize > f.swapSize {
			return errors.ErrNoBufs
		}
	}
	f.writeRecord(key, value)
	return nil
}

// Delete removes the record at the given index for the specified key.
// Index 0 is the first (oldest) live record with that key.
func (f *Flash) Delete(key uint16, index int) error {
	offset, err := f.findRecord(key, index)
	if err != nil {
		return err
	}
	// Mark as deleted by setting the key to deletedKey.
	binary.LittleEndian.PutUint16(f.swaps[f.swapIndex][offset:], deletedKey)
	return nil
}

// Get retrieves the value of the record at the given index for the specified
// key. Index 0 is the first (oldest) live record with that key.
func (f *Flash) Get(key uint16, index int) ([]byte, error) {
	offset, err := f.findRecord(key, index)
	if err != nil {
		return nil, err
	}
	length := int(binary.LittleEndian.Uint16(f.swaps[f.swapIndex][offset+2:]))
	valStart := offset + recordHeaderSize
	valEnd := valStart + length
	crcStored := binary.LittleEndian.Uint16(f.swaps[f.swapIndex][valEnd:])
	crcCalc := crc16(f.swaps[f.swapIndex][valStart:valEnd])
	if crcStored != crcCalc {
		return nil, errors.ErrFailed
	}
	result := make([]byte, length)
	copy(result, f.swaps[f.swapIndex][valStart:valEnd])
	return result, nil
}

// Set overwrites the first record for the given key, or creates a new one
// if no record exists. Any additional records with the same key are deleted.
func (f *Flash) Set(key uint16, value []byte) error {
	// Delete all existing records for this key.
	for {
		_, err := f.findRecord(key, 0)
		if err != nil {
			break
		}
		if err := f.Delete(key, 0); err != nil {
			return err
		}
	}
	return f.Add(key, value)
}

// writeRecord writes a record at the current swapUsed offset and advances it.
func (f *Flash) writeRecord(key uint16, value []byte) {
	swap := f.swaps[f.swapIndex]
	offset := f.swapUsed

	binary.LittleEndian.PutUint16(swap[offset:], key)
	binary.LittleEndian.PutUint16(swap[offset+2:], uint16(len(value)))
	copy(swap[offset+recordHeaderSize:], value)
	crc := crc16(value)
	binary.LittleEndian.PutUint16(swap[offset+recordHeaderSize+len(value):], crc)

	f.swapUsed += recordOverhead + len(value)
}

// findRecord locates the Nth live (non-deleted) record with the given key,
// returning its byte offset within the active swap. Returns ErrNotFound if
// the index-th occurrence does not exist.
func (f *Flash) findRecord(key uint16, index int) (int, error) {
	swap := f.swaps[f.swapIndex]
	offset := 0
	found := 0
	for offset+recordHeaderSize <= f.swapUsed {
		recKey := binary.LittleEndian.Uint16(swap[offset:])
		recLen := int(binary.LittleEndian.Uint16(swap[offset+2:]))
		recSize := recordOverhead + recLen
		if offset+recSize > f.swapUsed {
			break
		}
		if recKey == key {
			if found == index {
				return offset, nil
			}
			found++
		}
		offset += recSize
	}
	return 0, errors.ErrNotFound
}

// compact copies all live (non-deleted) records from the active swap to the
// inactive swap, then switches the active swap.
func (f *Flash) compact() error {
	newIndex := 1 - f.swapIndex
	// Clear the target swap.
	for i := range f.swaps[newIndex] {
		f.swaps[newIndex][i] = 0
	}
	oldSwap := f.swaps[f.swapIndex]
	newUsed := 0
	offset := 0
	for offset+recordHeaderSize <= f.swapUsed {
		recKey := binary.LittleEndian.Uint16(oldSwap[offset:])
		recLen := int(binary.LittleEndian.Uint16(oldSwap[offset+2:]))
		recSize := recordOverhead + recLen
		if offset+recSize > f.swapUsed {
			break
		}
		if recKey != deletedKey {
			copy(f.swaps[newIndex][newUsed:], oldSwap[offset:offset+recSize])
			newUsed += recSize
		}
		offset += recSize
	}
	// Clear the old swap.
	for i := range f.swaps[f.swapIndex] {
		f.swaps[f.swapIndex][i] = 0
	}
	f.swapIndex = newIndex
	f.swapUsed = newUsed
	return nil
}

// crc16 computes a CRC-16/CCITT-FALSE checksum over data.
func crc16(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}
