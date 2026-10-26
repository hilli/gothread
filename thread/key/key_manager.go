// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"github.com/hilli/gothread/crypto/hmac"
	"github.com/hilli/gothread/encoding"
)

// Key switch guard constants.
const (
	DefaultKeySwitchGuardTime    = 624 // ~93% of DefaultKeyRotationTime (672).
	KeySwitchGuardTimePercentage = 93  // Percentage of key rotation time.
)

// SeqUpdateFlag defines bit-flag constants for SetCurrentKeySequence behavior.
type SeqUpdateFlag uint8

const (
	// ApplySwitchGuard applies the key switch guard check.
	ApplySwitchGuard SeqUpdateFlag = 1 << 0
	// ForceUpdate ignores the key switch guard check.
	ForceUpdate SeqUpdateFlag = 0 << 0
	// ResetGuardTimer resets the guard timer on key sequence change.
	ResetGuardTimer SeqUpdateFlag = 1 << 1
	// GuardTimerUnchanged leaves the guard timer unchanged on key sequence change.
	GuardTimerUnchanged SeqUpdateFlag = 0 << 1
)

// threadString is the constant "Thread" used in key derivation.
var threadString = [6]byte{'T', 'h', 'r', 'e', 'a', 'd'}

// Manager handles Thread security material generation including
// network key management, key derivation, frame counters, and key rotation.
type Manager struct {
	networkKey NetworkKey
	pskc       Pskc
	isPskcSet  bool

	keySequence uint32
	mleKey      MleKey
	macKey      MacKey
	tempMleKey  MleKey
	tempMacKey  MacKey

	macFrameCounter  uint32
	mleFrameCounter  uint32
	storedMacCounter uint32
	storedMleCounter uint32

	kek             Kek
	kekFrameCounter uint32

	securityPolicy      SecurityPolicy
	keySwitchGuardTime  uint16
	keySwitchGuardTimer uint16
	hoursSinceRotation  uint16
}

// NewManager creates a new key Manager with default settings.
func NewManager() *Manager {
	m := &Manager{
		keySwitchGuardTime: DefaultKeySwitchGuardTime,
	}
	m.securityPolicy.SetToDefault()
	return m
}

// GetNetworkKey returns the current Thread Network Key.
func (m *Manager) GetNetworkKey() NetworkKey {
	return m.networkKey
}

// SetNetworkKey sets the Thread Network Key and recomputes derived keys.
func (m *Manager) SetNetworkKey(key NetworkKey) {
	if m.networkKey == key {
		return
	}
	m.networkKey = key
	m.keySequence = 0
	m.UpdateKeyMaterial()
	m.resetFrameCounters()
}

// IsPskcSet returns whether the PSKc has been explicitly set.
func (m *Manager) IsPskcSet() bool {
	return m.isPskcSet
}

// GetPskc returns the current PSKc.
func (m *Manager) GetPskc() Pskc {
	return m.pskc
}

// SetPskc sets the PSKc value.
func (m *Manager) SetPskc(pskc Pskc) {
	m.pskc = pskc
	m.isPskcSet = true
}

// GetCurrentKeySequence returns the current key sequence value.
func (m *Manager) GetCurrentKeySequence() uint32 {
	return m.keySequence
}

// SetCurrentKeySequence sets the key sequence and updates key material.
// The flags parameter controls whether the switch guard is applied
// and whether the guard timer is reset.
func (m *Manager) SetCurrentKeySequence(seq uint32, flags SeqUpdateFlag) {
	if seq == m.keySequence {
		return
	}

	if flags&ApplySwitchGuard != 0 && m.keySwitchGuardTimer > 0 {
		return
	}

	// Reset frame counters before updating keys.
	m.macFrameCounter = 0
	m.mleFrameCounter = 0

	m.keySequence = seq
	m.UpdateKeyMaterial()
	m.hoursSinceRotation = 0

	if flags&ResetGuardTimer != 0 {
		m.keySwitchGuardTimer = m.keySwitchGuardTime
	}
}

// GetCurrentMleKey returns the current MLE key derived from the current key sequence.
func (m *Manager) GetCurrentMleKey() MleKey {
	return m.mleKey
}

// GetCurrentMacKey returns the current MAC key derived from the current key sequence.
func (m *Manager) GetCurrentMacKey() MacKey {
	return m.macKey
}

// GetMacKeyId returns the key ID byte derived from the current key sequence.
// Thread uses the low 7 bits of the key sequence as the Key ID (mod 128),
// matching OpenThread's GetCurrentKeyId().
func (m *Manager) GetMacKeyId() uint8 { //nolint:revive // Preserve the exported API spelling for existing callers.
	return uint8(m.keySequence & 0x7F)
}

// GetTemporaryMleKey computes and returns the MLE key for the given key sequence.
func (m *Manager) GetTemporaryMleKey(seq uint32) MleKey {
	dk := m.ComputeKeys(seq)
	m.tempMleKey = dk.MleKey
	return m.tempMleKey
}

// GetTemporaryMacKey computes and returns the MAC key for the given key sequence.
func (m *Manager) GetTemporaryMacKey(seq uint32) MacKey {
	dk := m.ComputeKeys(seq)
	m.tempMacKey = dk.MacKey
	return m.tempMacKey
}

// ComputeKeys derives the MLE and MAC keys for the given key sequence.
//
// The derivation uses HMAC-SHA-256 with the Network Key as the HMAC key:
//
//	HMAC-SHA-256(key=NetworkKey, data=BigEndian(keySequence) || "Thread")
//	  → 32 bytes: MLE key (bytes 0-15) | MAC key (bytes 16-31)
func (m *Manager) ComputeKeys(seq uint32) DerivedKeys {
	var h hmac.Sha256
	var hash hmac.Hash

	h.Start(m.networkKey[:])

	var seqBuf [4]byte
	encoding.BigEndianWriteUint32(seq, seqBuf[:])
	h.Update(seqBuf[:])
	h.Update(threadString[:])
	h.Finish(&hash)

	var dk DerivedKeys
	copy(dk.MleKey[:], hash[:MleKeySize])
	copy(dk.MacKey[:], hash[MleKeySize:MleKeySize+MacKeySize])
	return dk
}

// UpdateKeyMaterial recomputes the MLE key from the current key sequence.
func (m *Manager) UpdateKeyMaterial() {
	dk := m.ComputeKeys(m.keySequence)
	m.mleKey = dk.MleKey
	m.macKey = dk.MacKey
}

// --- Frame counters ---

// GetMacFrameCounter returns the current MAC frame counter.
func (m *Manager) GetMacFrameCounter() uint32 {
	return m.macFrameCounter
}

// SetMacFrameCounter sets the MAC frame counter.
func (m *Manager) SetMacFrameCounter(counter uint32) {
	m.macFrameCounter = counter
}

// SetMacFrameCounterIfLarger sets the MAC frame counter only if the new value is larger.
func (m *Manager) SetMacFrameCounterIfLarger(counter uint32) {
	if counter > m.macFrameCounter {
		m.macFrameCounter = counter
	}
}

// MacFrameCounterUsed updates the MAC frame counter to indicate a value was used for TX.
func (m *Manager) MacFrameCounterUsed(counter uint32) {
	if m.macFrameCounter > counter {
		return
	}
	m.macFrameCounter = counter + 1
}

// GetMleFrameCounter returns the current MLE frame counter.
func (m *Manager) GetMleFrameCounter() uint32 {
	return m.mleFrameCounter
}

// SetMleFrameCounter sets the MLE frame counter.
func (m *Manager) SetMleFrameCounter(counter uint32) {
	m.mleFrameCounter = counter
}

// IncrementMleFrameCounter increments the MLE frame counter by one.
func (m *Manager) IncrementMleFrameCounter() {
	m.mleFrameCounter++
}

// --- Stored frame counters (non-volatile) ---

// GetStoredMacFrameCounter returns the stored MAC frame counter value.
func (m *Manager) GetStoredMacFrameCounter() uint32 {
	return m.storedMacCounter
}

// SetStoredMacFrameCounter sets the stored MAC frame counter value.
func (m *Manager) SetStoredMacFrameCounter(counter uint32) {
	m.storedMacCounter = counter
}

// GetStoredMleFrameCounter returns the stored MLE frame counter value.
func (m *Manager) GetStoredMleFrameCounter() uint32 {
	return m.storedMleCounter
}

// SetStoredMleFrameCounter sets the stored MLE frame counter value.
func (m *Manager) SetStoredMleFrameCounter(counter uint32) {
	m.storedMleCounter = counter
}

// --- KEK ---

// GetKek returns the current Key Encryption Key.
func (m *Manager) GetKek() Kek {
	return m.kek
}

// SetKek sets the Key Encryption Key and resets the KEK frame counter.
func (m *Manager) SetKek(kek Kek) {
	m.kek = kek
	m.kekFrameCounter = 0
}

// GetKekFrameCounter returns the current KEK frame counter.
func (m *Manager) GetKekFrameCounter() uint32 {
	return m.kekFrameCounter
}

// IncrementKekFrameCounter increments the KEK frame counter by one.
func (m *Manager) IncrementKekFrameCounter() {
	m.kekFrameCounter++
}

// --- Key switch guard ---

// GetKeySwitchGuardTime returns the key switch guard time in hours.
func (m *Manager) GetKeySwitchGuardTime() uint16 {
	return m.keySwitchGuardTime
}

// SetKeySwitchGuardTime sets the key switch guard time in hours.
// This is intended for testing; changing it renders the device non-compliant.
func (m *Manager) SetKeySwitchGuardTime(hours uint16) {
	m.keySwitchGuardTime = hours
}

// --- Security policy ---

// GetSecurityPolicy returns the current security policy.
func (m *Manager) GetSecurityPolicy() SecurityPolicy {
	return m.securityPolicy
}

// SetSecurityPolicy sets the security policy. If the rotation time is below
// the minimum, it is clamped to MinKeyRotationTime. The key switch guard
// time is recalculated as 93% of the rotation time when it changes.
func (m *Manager) SetSecurityPolicy(policy SecurityPolicy) {
	if policy.RotationTime < MinKeyRotationTime {
		policy.RotationTime = MinKeyRotationTime
	}

	if policy.RotationTime != m.securityPolicy.RotationTime {
		guardTime := uint32(policy.RotationTime)
		guardTime = guardTime * KeySwitchGuardTimePercentage / 100
		m.keySwitchGuardTime = uint16(guardTime)
	}

	m.securityPolicy = policy
	m.checkForKeyRotation()
}

// HandleKeyRotationTick should be called once per hour by the event loop
// to drive key rotation and guard timer countdown.
func (m *Manager) HandleKeyRotationTick() {
	m.hoursSinceRotation++

	if m.keySwitchGuardTimer > 0 {
		m.keySwitchGuardTimer--
	}

	m.checkForKeyRotation()
}

// checkForKeyRotation checks whether key rotation is due and performs it.
func (m *Manager) checkForKeyRotation() {
	if m.hoursSinceRotation >= m.securityPolicy.RotationTime {
		m.SetCurrentKeySequence(m.keySequence+1, ForceUpdate|ResetGuardTimer)
	}
}

// resetFrameCounters resets all frame counters to zero.
func (m *Manager) resetFrameCounters() {
	m.macFrameCounter = 0
	m.mleFrameCounter = 0
}

// Start initializes the key rotation timer state. The guard timer is cleared
// so that key rotation can proceed after the guard time elapses.
func (m *Manager) Start() {
	m.keySwitchGuardTimer = 0
	m.hoursSinceRotation = 0
}

// GetHoursSinceKeyRotation returns the number of hours since the last key rotation.
func (m *Manager) GetHoursSinceKeyRotation() uint16 {
	return m.hoursSinceRotation
}

// GetKeySwitchGuardTimer returns the remaining key switch guard timer value in hours.
func (m *Manager) GetKeySwitchGuardTimer() uint16 {
	return m.keySwitchGuardTimer
}
