// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package coap

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"time"

	goterrors "github.com/hilli/gothread/errors"
)

// NewEngineWithScheduler keeps all timer callbacks on the caller's owner loop.
// schedule must never invoke its callback inline. The reader is installed once;
// MID initialization and retransmission jitter errors propagate without fallback.
// NewEngine retains its existing standalone behavior.
func NewEngineWithScheduler(sender Sender, reader io.Reader, now func() time.Time,
	schedule func(time.Duration, func()) func()) (*Engine, error) {
	if sender == nil || reader == nil || now == nil || schedule == nil {
		return nil, goterrors.ErrInvalidArgs
	}
	var seed [2]byte
	if _, err := io.ReadFull(reader, seed[:]); err != nil {
		return nil, err
	}
	return &Engine{sender: sender, messageID: binary.BigEndian.Uint16(seed[:]), maxCacheSize: 8,
		nowFunc: now, ownerSchedule: schedule, runtimeEntropy: reader}, nil
}

func checkedInitialRetx(parameters TxParameters, reader io.Reader) (time.Duration, error) {
	base := time.Duration(parameters.AckTimeout) * time.Millisecond
	upper := time.Duration(uint64(parameters.AckTimeout)*uint64(parameters.AckRandomFactorNumerator)/
		uint64(parameters.AckRandomFactorDenominator)+1) * time.Millisecond
	if upper <= base {
		return base, nil
	}
	value, err := rand.Int(reader, big.NewInt(int64(upper-base)))
	if err != nil {
		return 0, err
	}
	return base + time.Duration(value.Int64()), nil
}
