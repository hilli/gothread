// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package netdata

// This file implements the Leader's authoritative copy of Thread Network Data.
// It mirrors OpenThread's Leader class from
// src/core/thread/network_data_leader.hpp and
// src/core/thread/network_data_leader_ftd.cpp.

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/mle"
)

// ---------------------------------------------------------------------------
// ChangedFlags — tracks what changed during a mutation
// ---------------------------------------------------------------------------

// ChangedFlags tracks whether network data changed and whether the stable
// subset was affected.
type ChangedFlags struct {
	changed       bool
	stableChanged bool
}

// Update records that a TLV was modified. The stable parameter indicates
// whether the affected TLV carries the stable flag.
func (f *ChangedFlags) Update(stable bool) {
	f.changed = true
	if stable {
		f.stableChanged = true
	}
}

// DidChange reports whether any network data changed.
func (f *ChangedFlags) DidChange() bool { return f.changed }

// DidStableChange reports whether stable network data changed.
func (f *ChangedFlags) DidStableChange() bool { return f.stableChanged }

// ---------------------------------------------------------------------------
// RouterChecker — interface for verifying router IDs
// ---------------------------------------------------------------------------

// RouterChecker is called by the Leader to verify that a router ID is
// allocated before accepting a data registration. In production this is
// backed by the routing table; in tests a stub can be used.
type RouterChecker interface {
	IsRouterIDAllocated(routerID uint8) bool
}

// ---------------------------------------------------------------------------
// Leader
// ---------------------------------------------------------------------------

// Leader manages the authoritative copy of Thread Network Data for the
// partition leader. It supports registering per-device data, removing entries
// when a device leaves, allocating 6LoWPAN context IDs, and tracking version
// numbers.
type Leader struct {
	data          MutableNetworkData
	contextIDs    *ContextIDManager
	version       uint8
	stableVersion uint8
	routerChecker RouterChecker
	onChanged     func() // optional callback invoked after versions change
}

// NewLeader creates a Leader with randomized initial version numbers and an
// empty network data buffer.
func NewLeader(rc RouterChecker) *Leader {
	l := &Leader{
		contextIDs:    NewContextIDManager(),
		routerChecker: rc,
	}
	l.Reset()
	return l
}

// Reset reinitialises the leader. Versions are randomized, all data and
// context IDs are cleared.
func (l *Leader) Reset() {
	var buf [2]byte
	_, _ = rand.Read(buf[:])
	l.version = buf[0]
	l.stableVersion = buf[1]
	l.data.Clear()
	l.contextIDs.Clear()
}

// SetOnChanged registers a callback invoked whenever version numbers change.
func (l *Leader) SetOnChanged(fn func()) {
	l.onChanged = fn
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

// Version returns the current full-set version number.
func (l *Leader) Version() uint8 { return l.version }

// StableVersion returns the current stable-subset version number.
func (l *Leader) StableVersion() uint8 { return l.stableVersion }

// Data returns the raw network data bytes.
func (l *Leader) Data() []byte { return l.data.Data() }

// StableData returns only the stable subset of the network data. Stable
// TLVs are those with the stable bit set in the TLV header. The returned
// slice is a freshly allocated copy.
func (l *Leader) StableData() []byte {
	var stable MutableNetworkData
	stable.CopyFrom(&l.data, true)
	// Return a copy so callers don't alias our internal buffer.
	out := make([]byte, stable.Len())
	copy(out, stable.Data())
	return out
}

// Len returns the length of the network data.
func (l *Leader) Len() int { return l.data.Len() }

// ContextIDManager returns the context ID manager for external timer
// integration.
func (l *Leader) ContextIDManager() *ContextIDManager { return l.contextIDs }

// ---------------------------------------------------------------------------
// Version management
// ---------------------------------------------------------------------------

// IncrementVersions bumps version numbers and signals a change.
func (l *Leader) IncrementVersions(includeStable bool) {
	if includeStable {
		l.stableVersion++
	}
	l.version++
	if l.onChanged != nil {
		l.onChanged()
	}
}

func (l *Leader) incrementVersions(flags *ChangedFlags) {
	if flags.DidChange() {
		l.IncrementVersions(flags.DidStableChange())
	}
}

// ---------------------------------------------------------------------------
// RemoveBorderRouter — public entry point
// ---------------------------------------------------------------------------

// RemoveBorderRouter removes all entries matching the given RLOC16 (or router
// ID, depending on mode) and increments versions if anything changed.
func (l *Leader) RemoveBorderRouter(rloc16 uint16, mode MatchMode) {
	var flags ChangedFlags
	l.removeRloc(rloc16, mode, nil, &flags)
	l.incrementVersions(&flags)
}

// ---------------------------------------------------------------------------
// RegisterNetworkData — the main registration flow
// ---------------------------------------------------------------------------

// RegisterNetworkData validates incoming network data from a router or child
// and merges it into the leader's authoritative copy.
//
// The rloc16 parameter is the registering device's RLOC16. The incoming
// parameter is the raw network data bytes from the registration message.
func (l *Leader) RegisterNetworkData(rloc16 uint16, incoming []byte) error {
	routerID := mle.RouterIDFromRLOC16(rloc16)
	if l.routerChecker != nil && !l.routerChecker.IsRouterIDAllocated(routerID) {
		return fmt.Errorf("router ID %d not allocated: %w", routerID, goterrors.ErrDrop)
	}

	// Validate the incoming data.
	if err := ValidateRegistration(incoming, rloc16); err != nil {
		return err
	}

	// Build a MutableNetworkData from the incoming bytes so we can use
	// FindPrefix / FindService on it during the exclude-aware removal.
	exclude := NewMutableNetworkData(incoming)

	var flags ChangedFlags

	// Remove old entries for this RLOC16, except those also present in the
	// incoming data (so unchanged entries are preserved in place).
	l.removeRloc(rloc16, MatchModeRLOC16, exclude, &flags)

	// Add new entries from the incoming data.
	if err := l.addIncoming(incoming, &flags); err != nil {
		return err
	}

	l.incrementVersions(&flags)
	return nil
}

// ---------------------------------------------------------------------------
// Validation of incoming registration data
// ---------------------------------------------------------------------------

// ValidateRegistration checks that incoming registration data is well-formed,
// all entries belong to the given RLOC16, and structure constraints are met.
func ValidateRegistration(data []byte, rloc16 uint16) error {
	m := NewMutableNetworkData(data)
	if err := m.Validate(); err != nil {
		return err
	}
	return validateRLOC16Ownership(data, rloc16)
}

// validateRLOC16Ownership verifies that every HasRoute, BorderRouter, and
// Server entry in data belongs to the given RLOC16.
func validateRLOC16Ownership(data []byte, rloc16 uint16) error {
	off := 0
	for off+TLVHeaderSize <= len(data) {
		typ, stable, length, err := ParseTLVHeader(data[off:])
		if err != nil {
			return err
		}
		tlvSize := TLVHeaderSize + int(length)
		if off+tlvSize > len(data) {
			return goterrors.ErrParse
		}

		switch typ {
		case TLVTypePrefix:
			if err := validatePrefixOwnership(data[off:off+tlvSize], stable, rloc16); err != nil {
				return err
			}
		case TLVTypeService:
			if err := validateServiceOwnership(data[off:off+tlvSize], stable, rloc16); err != nil {
				return err
			}
		}
		off += tlvSize
	}
	return nil
}

func validatePrefixOwnership(tlvData []byte, _ bool, rloc16 uint16) error {
	if len(tlvData) < TLVHeaderSize {
		return goterrors.ErrParse
	}
	_, _, outerLen, _ := ParseTLVHeader(tlvData)
	value := tlvData[TLVHeaderSize : TLVHeaderSize+int(outerLen)]
	info, err := ParsePrefixValue(value, false)
	if err != nil {
		return err
	}

	// Walk sub-TLVs inside the prefix value.
	subData := info.SubTLVsData
	subOff := 0
	for subOff+TLVHeaderSize <= len(subData) {
		sTyp, _, sLen, sErr := ParseTLVHeader(subData[subOff:])
		if sErr != nil {
			return sErr
		}
		sSize := TLVHeaderSize + int(sLen)
		if subOff+sSize > len(subData) {
			return goterrors.ErrParse
		}
		sValue := subData[subOff+TLVHeaderSize : subOff+sSize]

		switch sTyp {
		case TLVTypeHasRoute:
			if err := validateEntriesRLOC16(sValue, HasRouteEntrySize, rloc16); err != nil {
				return err
			}
		case TLVTypeBorderRouter:
			if err := validateEntriesRLOC16(sValue, BorderRouterEntrySize, rloc16); err != nil {
				return err
			}
		}
		subOff += sSize
	}
	return nil
}

func validateServiceOwnership(tlvData []byte, stable bool, rloc16 uint16) error {
	if len(tlvData) < TLVHeaderSize {
		return goterrors.ErrParse
	}
	_, _, outerLen, _ := ParseTLVHeader(tlvData)
	value := tlvData[TLVHeaderSize : TLVHeaderSize+int(outerLen)]
	info, err := ParseServiceValue(value, stable)
	if err != nil {
		return err
	}

	// Walk server sub-TLVs.
	subData := info.SubTLVsData
	subOff := 0
	for subOff+TLVHeaderSize <= len(subData) {
		sTyp, _, sLen, sErr := ParseTLVHeader(subData[subOff:])
		if sErr != nil {
			return sErr
		}
		sSize := TLVHeaderSize + int(sLen)
		if subOff+sSize > len(subData) {
			return goterrors.ErrParse
		}
		sValue := subData[subOff+TLVHeaderSize : subOff+sSize]

		if sTyp == TLVTypeServer {
			se, seErr := ParseServerValue(sValue)
			if seErr != nil {
				return seErr
			}
			if se.Server16 != rloc16 {
				return fmt.Errorf("server16 %04X != rloc16 %04X: %w", se.Server16, rloc16, goterrors.ErrParse)
			}
		}
		subOff += sSize
	}
	return nil
}

// validateEntriesRLOC16 checks that every fixed-size entry in data has the
// expected RLOC16 (stored big-endian in the first 2 bytes of each entry).
func validateEntriesRLOC16(data []byte, entrySize int, rloc16 uint16) error {
	for i := 0; i+entrySize <= len(data); i += entrySize {
		r := binary.BigEndian.Uint16(data[i:])
		if r != rloc16 {
			return fmt.Errorf("entry rloc16 %04X != %04X: %w", r, rloc16, goterrors.ErrParse)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// removeRloc — the exclude-aware removal
// ---------------------------------------------------------------------------

// removeRloc removes entries matching rloc16/mode from the leader's data,
// except those that also appear in exclude (so unchanged entries survive).
// If exclude is nil, all matching entries are removed.
func (l *Leader) removeRloc(rloc16 uint16, mode MatchMode, exclude *MutableNetworkData, flags *ChangedFlags) {
	off := 0
	for off < l.data.Len() {
		typ, _, _, err := ParseTLVHeader(l.data.Data()[off:])
		if err != nil {
			break
		}

		switch typ {
		case TLVTypePrefix:
			l.removeRlocInPrefix(off, rloc16, mode, exclude, flags)
			if l.updateParentTLV(off, flags) {
				continue // TLV removed, don't advance
			}
		case TLVTypeService:
			l.removeRlocInService(off, rloc16, mode, exclude, flags)
			if l.updateParentTLV(off, flags) {
				continue
			}
		}

		size, sErr := l.data.TLVSize(off)
		if sErr != nil {
			break
		}
		off += size
	}
}

// removeRlocInPrefix removes HasRoute and BorderRouter entries matching
// rloc16 from the prefix at parentOffset, excluding entries also present in
// exclude.
func (l *Leader) removeRlocInPrefix(parentOffset int, rloc16 uint16, mode MatchMode, exclude *MutableNetworkData, flags *ChangedFlags) {
	// Determine sub-TLV range.
	info, err := l.parsePrefixAt(parentOffset)
	if err != nil {
		return
	}

	// Find the matching prefix in the exclude data (if any).
	var excludePrefix = -1
	if exclude != nil {
		excludePrefix = exclude.FindPrefix(info.Prefix)
	}

	subStart := l.subTLVStart(parentOffset, TLVTypePrefix, info)
	if subStart < 0 {
		return
	}

	// Walk sub-TLVs and remove matching entries.
	subOff := subStart
	parentLen, _ := l.data.TLVLength(parentOffset)
	parentEnd := parentOffset + TLVHeaderSize + int(parentLen)

	for subOff < parentEnd {
		if subOff+TLVHeaderSize > l.data.Len() {
			break
		}
		sTyp, sStable, sLen, sErr := ParseTLVHeader(l.data.Data()[subOff:])
		if sErr != nil {
			break
		}
		sSize := TLVHeaderSize + int(sLen)

		switch sTyp {
		case TLVTypeHasRoute:
			l.removeMatchingEntriesInSub(parentOffset, subOff, HasRouteEntrySize,
				rloc16, mode, sStable, excludePrefix, TLVTypeHasRoute, exclude, flags)
			// Re-read sub-TLV length after removals.
			newLen, _ := l.data.TLVLength(subOff)
			if newLen == 0 {
				// Entry bytes were already removed; only the 2-byte header remains.
				l.removeSubTLV(parentOffset, subOff, TLVHeaderSize)
				parentLen, _ = l.data.TLVLength(parentOffset)
				parentEnd = parentOffset + TLVHeaderSize + int(parentLen)
				continue
			}
			newSize := TLVHeaderSize + int(newLen)
			subOff += newSize
			continue

		case TLVTypeBorderRouter:
			l.removeMatchingEntriesInSub(parentOffset, subOff, BorderRouterEntrySize,
				rloc16, mode, sStable, excludePrefix, TLVTypeBorderRouter, exclude, flags)
			newLen, _ := l.data.TLVLength(subOff)
			if newLen == 0 {
				// Entry bytes were already removed; only the 2-byte header remains.
				l.removeSubTLV(parentOffset, subOff, TLVHeaderSize)
				parentLen, _ = l.data.TLVLength(parentOffset)
				parentEnd = parentOffset + TLVHeaderSize + int(parentLen)
				continue
			}
			newSize := TLVHeaderSize + int(newLen)
			subOff += newSize
			continue
		}

		subOff += sSize
	}

	// Update context sub-TLV based on whether BorderRouter entries remain.
	l.updateContextAfterRemoval(parentOffset)
}

// removeRlocInService removes Server sub-TLVs matching rloc16 from the
// service at parentOffset.
func (l *Leader) removeRlocInService(parentOffset int, rloc16 uint16, mode MatchMode, exclude *MutableNetworkData, flags *ChangedFlags) {
	info, err := l.parseServiceAt(parentOffset)
	if err != nil {
		return
	}

	var excludeService = -1
	if exclude != nil {
		excludeService = exclude.FindService(info.EnterpriseNumber, info.ServiceData)
	}

	subStart := l.serviceSubTLVStart(parentOffset, info)
	if subStart < 0 {
		return
	}

	subOff := subStart
	parentLen, _ := l.data.TLVLength(parentOffset)
	parentEnd := parentOffset + TLVHeaderSize + int(parentLen)

	for subOff < parentEnd {
		if subOff+TLVHeaderSize > l.data.Len() {
			break
		}
		sTyp, sStable, sLen, sErr := ParseTLVHeader(l.data.Data()[subOff:])
		if sErr != nil {
			break
		}
		sSize := TLVHeaderSize + int(sLen)

		if sTyp == TLVTypeServer && int(sLen) >= 2 {
			serverRLOC := binary.BigEndian.Uint16(l.data.Data()[subOff+TLVHeaderSize:])
			if rloc16Matches(serverRLOC, rloc16, mode) &&
				!l.serverExistsInExclude(exclude, excludeService, sStable, l.data.Data()[subOff:subOff+sSize]) {
				flags.Update(sStable)
				l.removeSubTLV(parentOffset, subOff, sSize)
				parentLen, _ = l.data.TLVLength(parentOffset)
				parentEnd = parentOffset + TLVHeaderSize + int(parentLen)
				continue
			}
		}
		subOff += sSize
	}
}

// ---------------------------------------------------------------------------
// Sub-TLV entry removal helpers
// ---------------------------------------------------------------------------

// removeMatchingEntriesInSub removes fixed-size entries from a HasRoute or
// BorderRouter sub-TLV that match the given rloc16/mode and are not present
// in the exclude data.
func (l *Leader) removeMatchingEntriesInSub(
	parentOffset, subTLVOffset, entrySize int,
	rloc16 uint16, mode MatchMode,
	subStable bool,
	excludeParentOffset int,
	subType TLVType,
	exclude *MutableNetworkData,
	flags *ChangedFlags,
) {
	entryOff := subTLVOffset + TLVHeaderSize
	subLen, _ := l.data.TLVLength(subTLVOffset)
	subEnd := subTLVOffset + TLVHeaderSize + int(subLen)

	for entryOff+entrySize <= subEnd {
		entryRLOC := binary.BigEndian.Uint16(l.data.Data()[entryOff:])
		if rloc16Matches(entryRLOC, rloc16, mode) &&
			!l.entryExistsInExclude(exclude, excludeParentOffset, subStable, subType, entrySize, l.data.Data()[entryOff:entryOff+entrySize]) {
			flags.Update(subStable)
			// Remove the entry bytes and shrink both sub-TLV and parent lengths.
			_ = l.data.Remove(entryOff, entrySize)
			l.shrinkTLVLength(subTLVOffset, entrySize)
			l.shrinkTLVLength(parentOffset, entrySize)
			subLen -= uint8(entrySize)
			subEnd = subTLVOffset + TLVHeaderSize + int(subLen)
			continue // don't advance offset
		}
		entryOff += entrySize
	}
}

// entryExistsInExclude checks if an entry (from HasRoute or BorderRouter)
// exists in the exclude data's matching prefix sub-TLV.
func (l *Leader) entryExistsInExclude(exclude *MutableNetworkData, excludeParentOffset int, stable bool, subType TLVType, entrySize int, entry []byte) bool {
	if exclude == nil || excludeParentOffset < 0 {
		return false
	}
	// Find the matching sub-TLV (same type and stable flag) in the exclude prefix.
	excSubOff := exclude.FindSubTLVStable(excludeParentOffset, subType, stable)
	if excSubOff < 0 {
		return false
	}
	excSubLen, _ := exclude.TLVLength(excSubOff)
	excEntryOff := excSubOff + TLVHeaderSize
	excSubEnd := excSubOff + TLVHeaderSize + int(excSubLen)

	for excEntryOff+entrySize <= excSubEnd {
		if bytesEqual(exclude.Data()[excEntryOff:excEntryOff+entrySize], entry) {
			return true
		}
		excEntryOff += entrySize
	}
	return false
}

// serverExistsInExclude checks if a server sub-TLV exists in the exclude
// data's matching service.
func (l *Leader) serverExistsInExclude(exclude *MutableNetworkData, excludeServiceOffset int, stable bool, serverTLV []byte) bool {
	if exclude == nil || excludeServiceOffset < 0 {
		return false
	}
	excSubOff := exclude.FindSubTLVStable(excludeServiceOffset, TLVTypeServer, stable)
	if excSubOff < 0 {
		return false
	}
	excSize, _ := exclude.TLVSize(excSubOff)
	if excSize != len(serverTLV) {
		return false
	}
	return bytesEqual(exclude.Data()[excSubOff:excSubOff+excSize], serverTLV)
}

// ---------------------------------------------------------------------------
// Parent TLV cleanup
// ---------------------------------------------------------------------------

// updateParentTLV checks if a parent TLV (Prefix or Service) at the given
// offset has any sub-TLVs remaining. If not, the entire TLV is removed and
// the function returns true. Otherwise it updates the stable flag based on
// sub-TLV contents and returns false.
func (l *Leader) updateParentTLV(offset int, _ *ChangedFlags) bool {
	typ, _, outerLen, err := ParseTLVHeader(l.data.Data()[offset:])
	if err != nil {
		return false
	}
	tlvSize := TLVHeaderSize + int(outerLen)

	// Determine the sub-TLV start within this TLV.
	var subStart int
	switch typ {
	case TLVTypePrefix:
		info, pErr := l.parsePrefixAt(offset)
		if pErr != nil {
			return false
		}
		subStart = l.subTLVStart(offset, TLVTypePrefix, info)
	case TLVTypeService:
		info, sErr := l.parseServiceAt(offset)
		if sErr != nil {
			return false
		}
		subStart = l.serviceSubTLVStart(offset, info)
	default:
		return false
	}

	if subStart < 0 {
		return false
	}

	parentEnd := offset + tlvSize
	if subStart >= parentEnd {
		// No sub-TLVs — remove the whole TLV.
		_ = l.data.RemoveTLV(offset)
		return true
	}

	// Check if any sub-TLVs remain that are not Context TLVs.
	hasSubTLV := false
	hasStable := false
	subOff := subStart
	for subOff+TLVHeaderSize <= parentEnd && subOff < l.data.Len() {
		sTyp, sStable, sLen, sErr := ParseTLVHeader(l.data.Data()[subOff:])
		if sErr != nil {
			break
		}
		if sTyp != TLVTypeContext {
			hasSubTLV = true
			if sStable {
				hasStable = true
			}
		}
		subOff += TLVHeaderSize + int(sLen)
	}

	if !hasSubTLV {
		_ = l.data.RemoveTLV(offset)
		return true
	}

	// Update the parent's stable flag: stable if any sub-TLV is stable.
	l.setTLVStable(offset, hasStable)
	return false
}

// ---------------------------------------------------------------------------
// Context sub-TLV lifecycle
// ---------------------------------------------------------------------------

// updateContextAfterRemoval inspects the prefix at parentOffset and adjusts
// its Context sub-TLV based on whether any BorderRouter entries remain.
func (l *Leader) updateContextAfterRemoval(parentOffset int) {
	contextOff := l.data.FindSubTLV(parentOffset, TLVTypeContext)
	if contextOff < 0 {
		return // no context sub-TLV
	}

	// Check if any BorderRouter sub-TLV still exists.
	hasBR := l.data.FindSubTLV(parentOffset, TLVTypeBorderRouter) >= 0

	// Read the existing context info.
	ctxLen, _ := l.data.TLVLength(contextOff)
	if int(ctxLen) < ContextValueSize {
		return
	}
	ctxValue := l.data.Data()[contextOff+TLVHeaderSize : contextOff+TLVHeaderSize+ContextValueSize]
	ctx, err := ParseContextValue(ctxValue)
	if err != nil {
		return
	}

	if hasBR {
		// Ensure Compress is set and mark as in-use.
		ctx.Compress = true
		EncodeContextValue(ctxValue, ctx)
		l.contextIDs.MarkAsInUse(ctx.ContextID)
	} else {
		// Clear Compress and schedule for removal.
		ctx.Compress = false
		EncodeContextValue(ctxValue, ctx)
		l.contextIDs.ScheduleToRemove(ctx.ContextID, 0) // caller must supply real time via HandleTimer
	}
}

// RemoveContext removes the Context sub-TLV with the given context ID from
// all prefixes. This is called by the timer when a context ID's reuse delay
// expires.
func (l *Leader) RemoveContext(contextID uint8) {
	off := 0
	for off < l.data.Len() {
		typ, _, _, err := ParseTLVHeader(l.data.Data()[off:])
		if err != nil {
			break
		}
		if typ == TLVTypePrefix {
			l.removeContextFromPrefix(off, contextID)
			var flags ChangedFlags
			if l.updateParentTLV(off, &flags) {
				continue
			}
		}
		size, sErr := l.data.TLVSize(off)
		if sErr != nil {
			break
		}
		off += size
	}
	l.IncrementVersions(true) // context changes always affect stable data
}

// removeContextFromPrefix removes the Context sub-TLV with the given ID from
// the prefix at parentOffset.
func (l *Leader) removeContextFromPrefix(parentOffset int, contextID uint8) {
	contextOff := l.data.FindSubTLV(parentOffset, TLVTypeContext)
	if contextOff < 0 {
		return
	}
	ctxLen, _ := l.data.TLVLength(contextOff)
	if int(ctxLen) < ContextValueSize {
		return
	}
	ctxValue := l.data.Data()[contextOff+TLVHeaderSize : contextOff+TLVHeaderSize+ContextValueSize]
	ctx, err := ParseContextValue(ctxValue)
	if err != nil {
		return
	}
	if ctx.ContextID != contextID {
		return
	}
	ctxSize := TLVHeaderSize + int(ctxLen)
	l.removeSubTLV(parentOffset, contextOff, ctxSize)
}

// ---------------------------------------------------------------------------
// addIncoming — add entries from registration data
// ---------------------------------------------------------------------------

// addIncoming iterates the incoming registration data and adds new entries
// to the leader's network data.
func (l *Leader) addIncoming(data []byte, flags *ChangedFlags) error {
	off := 0
	for off+TLVHeaderSize <= len(data) {
		typ, stable, length, err := ParseTLVHeader(data[off:])
		if err != nil {
			return err
		}
		tlvSize := TLVHeaderSize + int(length)
		if off+tlvSize > len(data) {
			return goterrors.ErrParse
		}
		value := data[off+TLVHeaderSize : off+tlvSize]

		switch typ {
		case TLVTypePrefix:
			if err := l.addPrefix(value, stable, flags); err != nil {
				return err
			}
		case TLVTypeService:
			if err := l.addService(value, stable, flags); err != nil {
				return err
			}
		}
		off += tlvSize
	}
	return nil
}

// addPrefix adds or merges a prefix and its sub-TLVs.
func (l *Leader) addPrefix(value []byte, stable bool, flags *ChangedFlags) error {
	info, err := ParsePrefixValue(value, stable)
	if err != nil {
		return err
	}

	// Find or create the prefix TLV.
	prefixOff := l.data.FindPrefix(info.Prefix)
	if prefixOff < 0 {
		// Create a new Prefix TLV with just the domain-ID + prefix bytes.
		pBytes := prefixByteSize(info.Prefix.GetLength())
		headerValue := make([]byte, 0, 1+1+pBytes) // domainID + prefixLength + prefix
		headerValue = append(headerValue, info.DomainID, info.Prefix.GetLength())
		addrBytes := info.Prefix.GetBytes()
		headerValue = append(headerValue, addrBytes[:pBytes]...)

		prefixOff, err = l.data.AppendTLVSpace(TLVHeaderSize + len(headerValue))
		if err != nil {
			return fmt.Errorf("append prefix: %w", goterrors.ErrNoBufs)
		}
		EncodeTLVHeader(l.data.Data()[prefixOff:], TLVTypePrefix, stable, uint8(len(headerValue)))
		copy(l.data.Data()[prefixOff+TLVHeaderSize:], headerValue)
	}

	// Walk the incoming prefix's sub-TLVs and add them.
	subData := info.SubTLVsData
	subOff := 0
	for subOff+TLVHeaderSize <= len(subData) {
		sTyp, sStable, sLen, sErr := ParseTLVHeader(subData[subOff:])
		if sErr != nil {
			break
		}
		sSize := TLVHeaderSize + int(sLen)
		if subOff+sSize > len(subData) {
			break
		}
		sValue := subData[subOff+TLVHeaderSize : subOff+sSize]

		switch sTyp {
		case TLVTypeHasRoute:
			if err := l.addHasRoute(prefixOff, sValue, sStable, HasRouteEntrySize, flags); err != nil {
				return err
			}
		case TLVTypeBorderRouter:
			if err := l.addBorderRouter(prefixOff, sValue, sStable, flags); err != nil {
				return err
			}
		}
		subOff += sSize
	}

	// Update the prefix TLV (remove if empty, update stable flag).
	var dummy ChangedFlags
	l.updateParentTLV(prefixOff, &dummy)
	return nil
}

// addHasRoute adds HasRoute entries to an existing prefix.
func (l *Leader) addHasRoute(prefixOff int, entryData []byte, stable bool, entrySize int, flags *ChangedFlags) error {
	// Find or create the HasRoute sub-TLV.
	hrOff := l.data.FindSubTLVStable(prefixOff, TLVTypeHasRoute, stable)
	if hrOff < 0 {
		// Insert a new HasRoute sub-TLV header.
		hrOff2, err := l.insertSubTLV(prefixOff, TLVTypeHasRoute, stable, 0)
		if err != nil {
			return err
		}
		hrOff = hrOff2
	}

	// Add each entry if not already present.
	for i := 0; i+entrySize <= len(entryData); i += entrySize {
		entry := entryData[i : i+entrySize]
		if l.subTLVContainsEntry(hrOff, entrySize, entry) {
			continue
		}
		// Insert the entry at the end of the HasRoute sub-TLV.
		if err := l.insertEntryInSub(prefixOff, hrOff, entry); err != nil {
			return err
		}
		flags.Update(stable)
	}
	return nil
}

// addBorderRouter adds BorderRouter entries to an existing prefix, allocating
// a Context ID if needed.
func (l *Leader) addBorderRouter(prefixOff int, entryData []byte, stable bool, flags *ChangedFlags) error {
	// Check if a Context sub-TLV already exists.
	contextOff := l.data.FindSubTLV(prefixOff, TLVTypeContext)

	if contextOff < 0 {
		// Need to allocate a new context ID.
		contextID, err := l.contextIDs.GetUnallocatedID()
		if err != nil {
			return fmt.Errorf("no context IDs available: %w", goterrors.ErrNoBufs)
		}

		// Find or create the BorderRouter sub-TLV first (so the prefix TLV
		// exists and has room).
		if l.data.FindSubTLVStable(prefixOff, TLVTypeBorderRouter, stable) < 0 {
			if _, brErr := l.insertSubTLV(prefixOff, TLVTypeBorderRouter, stable, 0); brErr != nil {
				return brErr
			}
		}

		// Now insert the Context sub-TLV.
		info, _ := l.parsePrefixAt(prefixOff)
		ctx := ContextInfo{
			ContextID:     contextID,
			Compress:      true,
			ContextLength: info.Prefix.GetLength(),
		}
		ctxBytes := AppendContextValue(nil, ctx)
		ctxOff, ctxErr := l.insertSubTLV(prefixOff, TLVTypeContext, true, len(ctxBytes))
		if ctxErr != nil {
			return ctxErr
		}
		copy(l.data.Data()[ctxOff+TLVHeaderSize:], ctxBytes)

		l.contextIDs.MarkAsInUse(contextID)

		// Now add the entries to the BorderRouter sub-TLV. Re-find it since
		// offsets may have shifted.
		brOff := l.data.FindSubTLVStable(prefixOff, TLVTypeBorderRouter, stable)
		if brOff < 0 {
			return goterrors.ErrParse
		}

		for i := 0; i+BorderRouterEntrySize <= len(entryData); i += BorderRouterEntrySize {
			entry := entryData[i : i+BorderRouterEntrySize]
			if l.subTLVContainsEntry(brOff, BorderRouterEntrySize, entry) {
				continue
			}
			if err := l.insertEntryInSub(prefixOff, brOff, entry); err != nil {
				return err
			}
			flags.Update(stable)
		}
		return nil
	}

	// Context already exists — just add entries.
	if l.data.FindSubTLVStable(prefixOff, TLVTypeBorderRouter, stable) < 0 {
		if _, brErr := l.insertSubTLV(prefixOff, TLVTypeBorderRouter, stable, 0); brErr != nil {
			return brErr
		}
	}

	// Ensure context is marked as in-use and Compress is set.
	ctxLen, _ := l.data.TLVLength(contextOff)
	if int(ctxLen) >= ContextValueSize {
		ctxValue := l.data.Data()[contextOff+TLVHeaderSize : contextOff+TLVHeaderSize+ContextValueSize]
		ctx, _ := ParseContextValue(ctxValue)
		ctx.Compress = true
		EncodeContextValue(ctxValue, ctx)
		l.contextIDs.MarkAsInUse(ctx.ContextID)
	}

	// Re-find brOff since insert/context operations may have shifted offsets.
	brOff := l.data.FindSubTLVStable(prefixOff, TLVTypeBorderRouter, stable)
	if brOff < 0 {
		return goterrors.ErrParse
	}

	for i := 0; i+BorderRouterEntrySize <= len(entryData); i += BorderRouterEntrySize {
		entry := entryData[i : i+BorderRouterEntrySize]
		if l.subTLVContainsEntry(brOff, BorderRouterEntrySize, entry) {
			continue
		}
		if err := l.insertEntryInSub(prefixOff, brOff, entry); err != nil {
			return err
		}
		flags.Update(stable)
	}
	return nil
}

// addService adds or merges a service and its server sub-TLVs.
func (l *Leader) addService(value []byte, stable bool, flags *ChangedFlags) error {
	info, err := ParseServiceValue(value, stable)
	if err != nil {
		return err
	}

	serviceOff := l.data.FindService(info.EnterpriseNumber, info.ServiceData)
	if serviceOff < 0 {
		// Create a new service TLV.
		svcValue := AppendServiceValue(nil, info)
		// We need to build: TLV header + service-value-without-subTLVs
		// Sub-TLVs will be added via insertSubTLV.
		headerOnly := ServiceTLVInfo{
			ServiceID:        info.ServiceID,
			EnterpriseNumber: info.EnterpriseNumber,
			ServiceData:      info.ServiceData,
			SubTLVsData:      nil,
			Stable:           stable,
		}
		hdrBytes := AppendServiceValue(nil, headerOnly)
		serviceOff, err = l.data.AppendTLVSpace(TLVHeaderSize + len(hdrBytes))
		if err != nil {
			return fmt.Errorf("append service: %w", goterrors.ErrNoBufs)
		}
		EncodeTLVHeader(l.data.Data()[serviceOff:], TLVTypeService, stable, uint8(len(hdrBytes)))
		copy(l.data.Data()[serviceOff+TLVHeaderSize:], hdrBytes)
		_ = svcValue // consumed info for header
	}

	// Walk incoming server sub-TLVs and add them.
	subData := info.SubTLVsData
	subOff := 0
	for subOff+TLVHeaderSize <= len(subData) {
		sTyp, sStable, sLen, sErr := ParseTLVHeader(subData[subOff:])
		if sErr != nil {
			break
		}
		sSize := TLVHeaderSize + int(sLen)
		if subOff+sSize > len(subData) {
			break
		}

		if sTyp == TLVTypeServer {
			serverBytes := subData[subOff : subOff+sSize]
			if !l.serviceContainsServer(serviceOff, sStable, serverBytes) {
				// Insert the entire Server sub-TLV.
				if err := l.insertRawSubTLV(serviceOff, serverBytes); err != nil {
					return err
				}
				flags.Update(sStable)
			}
		}
		subOff += sSize
	}

	// Cleanup.
	var dummy ChangedFlags
	l.updateParentTLV(serviceOff, &dummy)
	return nil
}

// ---------------------------------------------------------------------------
// Context lookup
// ---------------------------------------------------------------------------

// FindContextForPrefix searches the network data for the longest-matching
// prefix that has a Context sub-TLV and returns its ContextInfo. Returns
// ErrNotFound if no context matches.
func (l *Leader) FindContextForPrefix(prefix ip6.Prefix) (ContextInfo, error) {
	var best ContextInfo
	found := false

	off := 0
	for off < l.data.Len() {
		typ, _, _, err := ParseTLVHeader(l.data.Data()[off:])
		if err != nil {
			break
		}
		if typ == TLVTypePrefix {
			info, pErr := l.parsePrefixAt(off)
			if pErr == nil && info.Prefix.ContainsPrefix(prefix) {
				ctxOff := l.data.FindSubTLV(off, TLVTypeContext)
				if ctxOff >= 0 {
					ctxLen, _ := l.data.TLVLength(ctxOff)
					if int(ctxLen) >= ContextValueSize {
						ctx, cErr := ParseContextValue(l.data.Data()[ctxOff+TLVHeaderSize : ctxOff+TLVHeaderSize+ContextValueSize])
						if cErr == nil && (!found || info.Prefix.GetLength() > best.ContextLength) {
							best = ctx
							best.ContextLength = info.Prefix.GetLength()
							found = true
						}
					}
				}
			}
		}
		size, sErr := l.data.TLVSize(off)
		if sErr != nil {
			break
		}
		off += size
	}
	if !found {
		return ContextInfo{}, goterrors.ErrNotFound
	}
	return best, nil
}

// FindContextForID searches the network data for a prefix whose Context
// sub-TLV has the given ID and returns the ContextInfo. Returns ErrNotFound
// if no such context exists.
func (l *Leader) FindContextForID(contextID uint8) (ContextInfo, ip6.Prefix, error) {
	off := 0
	for off < l.data.Len() {
		typ, _, _, err := ParseTLVHeader(l.data.Data()[off:])
		if err != nil {
			break
		}
		if typ == TLVTypePrefix {
			info, pErr := l.parsePrefixAt(off)
			if pErr == nil {
				ctxOff := l.data.FindSubTLV(off, TLVTypeContext)
				if ctxOff >= 0 {
					ctxLen, _ := l.data.TLVLength(ctxOff)
					if int(ctxLen) >= ContextValueSize {
						ctx, cErr := ParseContextValue(l.data.Data()[ctxOff+TLVHeaderSize : ctxOff+TLVHeaderSize+ContextValueSize])
						if cErr == nil && ctx.ContextID == contextID {
							return ctx, info.Prefix, nil
						}
					}
				}
			}
		}
		size, sErr := l.data.TLVSize(off)
		if sErr != nil {
			break
		}
		off += size
	}
	return ContextInfo{}, ip6.Prefix{}, goterrors.ErrNotFound
}

// ---------------------------------------------------------------------------
// Internal TLV manipulation helpers
// ---------------------------------------------------------------------------

// parsePrefixAt parses the Prefix TLV at the given offset.
func (l *Leader) parsePrefixAt(offset int) (PrefixTLVInfo, error) {
	_, stable, outerLen, err := ParseTLVHeader(l.data.Data()[offset:])
	if err != nil {
		return PrefixTLVInfo{}, err
	}
	value := l.data.Data()[offset+TLVHeaderSize : offset+TLVHeaderSize+int(outerLen)]
	return ParsePrefixValue(value, stable)
}

// parseServiceAt parses the Service TLV at the given offset.
func (l *Leader) parseServiceAt(offset int) (ServiceTLVInfo, error) {
	_, stable, outerLen, err := ParseTLVHeader(l.data.Data()[offset:])
	if err != nil {
		return ServiceTLVInfo{}, err
	}
	value := l.data.Data()[offset+TLVHeaderSize : offset+TLVHeaderSize+int(outerLen)]
	return ParseServiceValue(value, stable)
}

// subTLVStart returns the byte offset of the first sub-TLV within a Prefix
// TLV at parentOffset. Returns -1 on error.
func (l *Leader) subTLVStart(parentOffset int, _ TLVType, info PrefixTLVInfo) int {
	// Prefix value layout: domainID(1) + prefixLength(1) + prefix(ceil(length/8)) + sub-TLVs
	pBytes := prefixByteSize(info.Prefix.GetLength())
	return parentOffset + TLVHeaderSize + 1 + 1 + pBytes
}

// serviceSubTLVStart returns the byte offset of the first sub-TLV within a
// Service TLV at parentOffset.
func (l *Leader) serviceSubTLVStart(parentOffset int, info ServiceTLVInfo) int {
	// Service value layout:
	//   flags(1) [+ enterpriseNumber(4)] + serviceDataLength(1) + serviceData(N) + sub-TLVs
	n := 1 // flags byte
	if info.EnterpriseNumber != ThreadEnterpriseNumber {
		n += 4
	}
	n += 1 + len(info.ServiceData)
	return parentOffset + TLVHeaderSize + n
}

// insertSubTLV inserts a new sub-TLV header (and optional value space) at the
// end of a parent TLV and returns the offset of the new sub-TLV.
func (l *Leader) insertSubTLV(parentOffset int, typ TLVType, stable bool, valueLen int) (int, error) {
	parentLen, _ := l.data.TLVLength(parentOffset)
	insertOff := parentOffset + TLVHeaderSize + int(parentLen)
	totalSize := TLVHeaderSize + valueLen

	if !l.data.CanInsert(totalSize) {
		return -1, goterrors.ErrNoBufs
	}
	if err := l.data.Insert(insertOff, totalSize); err != nil {
		return -1, err
	}
	l.growTLVLength(parentOffset, totalSize)
	EncodeTLVHeader(l.data.Data()[insertOff:], typ, stable, uint8(valueLen))
	return insertOff, nil
}

// insertRawSubTLV inserts raw sub-TLV bytes at the end of a parent TLV.
func (l *Leader) insertRawSubTLV(parentOffset int, raw []byte) error {
	parentLen, _ := l.data.TLVLength(parentOffset)
	insertOff := parentOffset + TLVHeaderSize + int(parentLen)

	if !l.data.CanInsert(len(raw)) {
		return goterrors.ErrNoBufs
	}
	if err := l.data.Insert(insertOff, len(raw)); err != nil {
		return err
	}
	copy(l.data.Data()[insertOff:], raw)
	l.growTLVLength(parentOffset, len(raw))
	return nil
}

// insertEntryInSub inserts entry bytes at the end of a sub-TLV and grows
// both the sub-TLV and parent TLV lengths.
func (l *Leader) insertEntryInSub(parentOffset, subTLVOffset int, entry []byte) error {
	subLen, _ := l.data.TLVLength(subTLVOffset)
	insertOff := subTLVOffset + TLVHeaderSize + int(subLen)

	if !l.data.CanInsert(len(entry)) {
		return goterrors.ErrNoBufs
	}
	if err := l.data.Insert(insertOff, len(entry)); err != nil {
		return err
	}
	copy(l.data.Data()[insertOff:], entry)
	l.growTLVLength(subTLVOffset, len(entry))
	l.growTLVLength(parentOffset, len(entry))
	return nil
}

// removeSubTLV removes a sub-TLV and shrinks the parent TLV length.
func (l *Leader) removeSubTLV(parentOffset, subOffset, subSize int) {
	_ = l.data.Remove(subOffset, subSize)
	l.shrinkTLVLength(parentOffset, subSize)
}

// subTLVContainsEntry checks if the sub-TLV at subOffset contains an entry
// with the given bytes.
func (l *Leader) subTLVContainsEntry(subOffset, entrySize int, entry []byte) bool {
	subLen, _ := l.data.TLVLength(subOffset)
	entryOff := subOffset + TLVHeaderSize
	subEnd := subOffset + TLVHeaderSize + int(subLen)

	for entryOff+entrySize <= subEnd {
		if bytesEqual(l.data.Data()[entryOff:entryOff+entrySize], entry) {
			return true
		}
		entryOff += entrySize
	}
	return false
}

// serviceContainsServer checks if the service at serviceOffset contains a
// Server sub-TLV matching the given raw bytes and stable flag.
func (l *Leader) serviceContainsServer(serviceOffset int, stable bool, serverTLV []byte) bool {
	srvOff := l.data.FindSubTLVStable(serviceOffset, TLVTypeServer, stable)
	if srvOff < 0 {
		return false
	}
	srvSize, _ := l.data.TLVSize(srvOff)
	if srvSize != len(serverTLV) {
		return false
	}
	return bytesEqual(l.data.Data()[srvOff:srvOff+srvSize], serverTLV)
}

// growTLVLength increases the TLV length field at offset by n.
func (l *Leader) growTLVLength(offset, n int) {
	cur, err := l.data.TLVLength(offset)
	if err != nil {
		return
	}
	_ = l.data.SetTLVLength(offset, cur+uint8(n))
}

// shrinkTLVLength decreases the TLV length field at offset by n.
func (l *Leader) shrinkTLVLength(offset, n int) {
	cur, err := l.data.TLVLength(offset)
	if err != nil {
		return
	}
	if int(cur) >= n {
		_ = l.data.SetTLVLength(offset, cur-uint8(n))
	}
}

// setTLVStable sets or clears the stable bit in the TLV header at offset.
func (l *Leader) setTLVStable(offset int, stable bool) {
	if offset >= l.data.Len() {
		return
	}
	b := l.data.Data()[offset]
	typ := b >> 1
	if stable {
		l.data.Data()[offset] = (typ << 1) | 1
	} else {
		l.data.Data()[offset] = typ << 1
	}
}

// ---------------------------------------------------------------------------
// Commissioning Data
// ---------------------------------------------------------------------------

// SetCommissioningData stores the given MeshCoP TLV bytes as the
// CommissioningData TLV in the network data. If a CommissioningData TLV
// already exists it is replaced; otherwise a new one is appended.
// CommissioningData is always unstable (stable_bit=0). An empty data slice
// removes the existing CommissioningData TLV. Versions are bumped (full
// version only, not stable).
func (l *Leader) SetCommissioningData(data []byte) error {
	// Remove any existing CommissioningData TLV.
	off := l.data.FindTLV(TLVTypeCommissioningData, false)
	if off >= 0 {
		_ = l.data.RemoveTLV(off)
	}

	// If data is empty the caller wants to remove commissioning data.
	if len(data) == 0 {
		l.IncrementVersions(false)
		return nil
	}

	// Append a new CommissioningData TLV: header(2) + MeshCoP TLV payload.
	totalSize := TLVHeaderSize + len(data)
	newOff, err := l.data.AppendTLVSpace(totalSize)
	if err != nil {
		return fmt.Errorf("append commissioning data: %w", goterrors.ErrNoBufs)
	}
	EncodeTLVHeader(l.data.Data()[newOff:], TLVTypeCommissioningData, false, uint8(len(data)))
	copy(l.data.Data()[newOff+TLVHeaderSize:], data)

	l.IncrementVersions(false)
	return nil
}

// GetCommissioningData returns the raw MeshCoP TLV bytes stored in the
// CommissioningData network data TLV, or nil if no such TLV exists.
func (l *Leader) GetCommissioningData() []byte {
	off := l.data.FindTLV(TLVTypeCommissioningData, false)
	if off < 0 {
		return nil
	}
	length, err := l.data.TLVLength(off)
	if err != nil {
		return nil
	}
	result := make([]byte, length)
	copy(result, l.data.Data()[off+TLVHeaderSize:off+TLVHeaderSize+int(length)])
	return result
}

// RemoveCommissioningData removes the CommissioningData TLV from network data
// and bumps versions.
func (l *Leader) RemoveCommissioningData() {
	off := l.data.FindTLV(TLVTypeCommissioningData, false)
	if off < 0 {
		return
	}
	_ = l.data.RemoveTLV(off)
	l.IncrementVersions(false)
}
