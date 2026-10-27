// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math"

	"github.com/hilli/gothread/common/settings"
	goterrors "github.com/hilli/gothread/errors"
)

// FrameCounterReservation is the number of counters durably reserved at once.
// A restart skips the unused part of each reservation.
const FrameCounterReservation uint32 = 1024

// ErrFrameCounterExhausted means no further counter can be allocated.
// MaxUint32 is the exhausted sentinel and is never transmitted.
var ErrFrameCounterExhausted = errors.New("key: frame counter exhausted")

// EnablePersistence restores key sequence and reserved counter limits.
// allowCreate must be false when credentials already exist without counter
// state: their previous counter usage cannot safely be inferred.
// Settings writes must be atomic, durable before returning, and never rolled
// back. Only one live manager may use a settings namespace.
func (m *Manager) EnablePersistence(s *settings.Settings, allowCreate bool) error {
	m.settings = s
	data, err := s.ReadNetworkInfo()
	if errors.Is(err, settings.ErrNotFound) && allowCreate {
		err = m.saveCounterState(m.macFrameCounter, m.mleFrameCounter, m.networkKey, m.keySequence)
	} else if err == nil {
		if len(data) != 49 || data[0] != 1 ||
			crc32.ChecksumIEEE(data[:45]) != binary.BigEndian.Uint32(data[45:]) {
			err = goterrors.ErrParse
		} else {
			copy(m.savedKeyHash[:], data[1:33])
			m.savedKeySequence = binary.BigEndian.Uint32(data[33:37])
			m.storedMacCounter = binary.BigEndian.Uint32(data[37:41])
			m.storedMleCounter = binary.BigEndian.Uint32(data[41:45])
			m.macFrameCounter = m.storedMacCounter
			m.mleFrameCounter = m.storedMleCounter
			if sha256.Sum256(m.networkKey[:]) == m.savedKeyHash {
				m.keySequence = m.savedKeySequence
				m.UpdateKeyMaterial()
			}
		}
	}
	if err != nil {
		m.persistenceErr = fmt.Errorf("key: restore counter state: %w", err)
	}
	return m.persistenceErr
}

// PersistenceError reports a latched persistence failure. A fresh manager must
// restore durable state before secured transmission can resume after failure.
func (m *Manager) PersistenceError() error { return m.persistenceErr }

func (m *Manager) saveCounterState(macLimit, mleLimit uint32, networkKey NetworkKey, sequence uint32) error {
	var data [49]byte
	data[0] = 1
	hash := sha256.Sum256(networkKey[:])
	copy(data[1:33], hash[:])
	binary.BigEndian.PutUint32(data[33:37], sequence)
	binary.BigEndian.PutUint32(data[37:41], macLimit)
	binary.BigEndian.PutUint32(data[41:45], mleLimit)
	binary.BigEndian.PutUint32(data[45:], crc32.ChecksumIEEE(data[:45]))
	if err := m.settings.WriteNetworkInfo(data[:]); err != nil {
		m.persistenceErr = fmt.Errorf("key: persist counter reservation: %w", err)
		return m.persistenceErr
	}
	m.savedKeyHash = hash
	m.savedKeySequence = sequence
	m.storedMacCounter = macLimit
	m.storedMleCounter = mleLimit
	return nil
}

// AllocateMacFrameCounter reserves durable space before consuming a MAC
// counter. The caller must allocate before encryption, not after transmission.
func (m *Manager) AllocateMacFrameCounter() (uint32, error) {
	return m.allocateFrameCounter(&m.macFrameCounter, true)
}

// AllocateMleFrameCounter reserves durable space before consuming an MLE counter.
func (m *Manager) AllocateMleFrameCounter() (uint32, error) {
	return m.allocateFrameCounter(&m.mleFrameCounter, false)
}

func (m *Manager) allocateFrameCounter(next *uint32, mac bool) (uint32, error) {
	if m.persistenceErr != nil {
		return 0, m.persistenceErr
	}
	if *next == math.MaxUint32 {
		return 0, ErrFrameCounterExhausted
	}
	if m.settings != nil {
		limit := m.storedMleCounter
		if mac {
			limit = m.storedMacCounter
		}
		if *next >= limit {
			newLimit := uint64(*next) + uint64(FrameCounterReservation)
			if newLimit > math.MaxUint32 {
				newLimit = math.MaxUint32
			}
			macLimit, mleLimit := m.storedMacCounter, m.storedMleCounter
			if mac {
				macLimit = uint32(newLimit)
			} else {
				mleLimit = uint32(newLimit)
			}
			if err := m.saveCounterState(macLimit, mleLimit, m.networkKey, m.keySequence); err != nil {
				return 0, err
			}
		}
	}
	counter := *next
	*next++
	return counter, nil
}
