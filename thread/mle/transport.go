// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/key"
)

// Transport abstracts the UDP send/receive layer for MLE messages.
//
// In a real Thread stack the MLE messages are exchanged over UDP port 19788
// using link-local and mesh-local IPv6 addresses. This interface decouples
// the MLE protocol logic from the actual network I/O so the state machine
// can be tested without a live radio.
type Transport interface {
	// SendMLE sends a finalized MLE message to the given destination.
	// The message bytes should already be encrypted/finalized when secured.
	SendMLE(msg []byte, dst ip6.Address) error

	// GetExtAddress returns the local device's extended (EUI-64) MAC address.
	GetExtAddress() types.ExtAddress

	// GetLinkLocalAddress returns the local device's link-local IPv6 address.
	GetLinkLocalAddress() ip6.Address

	// GetMeshLocalAddress returns the local device's mesh-local EID IPv6 address.
	GetMeshLocalAddress() ip6.Address

	// GetLinkLocalAllRoutersMulticast returns the link-local all Thread routers
	// multicast address (ff02::2 for MLE Parent Request).
	GetLinkLocalAllRoutersMulticast() ip6.Address
}

// RxInfo holds metadata about a received MLE message.
//
// This is analogous to OpenThread's Mle::RxInfo which carries the source
// address, key information, and the parsed message state needed by
// individual command handlers.
type RxInfo struct {
	// SrcAddr is the source extended MAC address of the sender.
	SrcAddr types.ExtAddress

	// SrcIP is the source IPv6 address from the UDP header.
	SrcIP ip6.Address

	// DstIP is the destination IPv6 address from the UDP header.
	DstIP ip6.Address

	// LinkMarginRaw is the raw link margin in dB (from the received signal).
	LinkMarginRaw uint8

	// KeySequence is the key sequence from the security header (for secured messages).
	KeySequence uint32

	// FrameCounter is the frame counter from the security header.
	FrameCounter uint32

	// Command is the MLE command byte from the decrypted payload.
	Command Command

	// TLVs is the list of parsed TLVs from the decrypted payload.
	TLVs []TLV

	// IsSecured is true if the message was secured (not a Discovery message).
	IsSecured bool

	// Neighbor is the neighbor entry associated with the sender, if known.
	// May be nil for unknown senders (e.g., during Parent Response).
	Neighbor *Neighbor
}

// KeyProvider abstracts access to the key material needed for MLE
// message encryption and decryption. This is typically satisfied by
// [key.Manager].
type KeyProvider interface {
	// GetCurrentKeySequence returns the current key sequence value.
	GetCurrentKeySequence() uint32

	// GetCurrentMleKey returns the MLE key for the current key sequence.
	GetCurrentMleKey() key.MleKey

	// GetTemporaryMleKey computes and returns the MLE key for an arbitrary
	// key sequence (used when receiving messages with a different sequence).
	GetTemporaryMleKey(seq uint32) key.MleKey

	// GetMleFrameCounter returns the current MLE frame counter for sending.
	GetMleFrameCounter() uint32

	// IncrementMleFrameCounter increments the MLE frame counter after sending.
	IncrementMleFrameCounter()

	// GetMacFrameCounter returns the current MAC frame counter.
	GetMacFrameCounter() uint32

	// SetCurrentKeySequence updates the key sequence with the given flags.
	SetCurrentKeySequence(seq uint32, flags key.SeqUpdateFlag)
}

// DatasetProvider abstracts access to the Active and Pending operational
// datasets. MLE handlers use this to obtain real timestamps and dataset
// TLV payloads instead of zero-value placeholders.
//
// In production, this is satisfied by the Instance struct which delegates
// to meshcop.ActiveDatasetManager and meshcop.PendingDatasetManager.
type DatasetProvider interface {
	// GetActiveTimestamp returns the current Active Dataset timestamp.
	GetActiveTimestamp() meshcop.Timestamp

	// GetPendingTimestamp returns the current Pending Dataset timestamp.
	GetPendingTimestamp() meshcop.Timestamp

	// ReadActiveDataset returns the Active Dataset as raw TLV bytes,
	// or nil if no dataset is configured.
	ReadActiveDataset() []byte

	// ReadPendingDataset returns the Pending Dataset as raw TLV bytes,
	// or nil if no dataset is configured.
	ReadPendingDataset() []byte
}
