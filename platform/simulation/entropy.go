// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package simulation

import (
	"crypto/rand"

	"github.com/hilli/gothread/platform"
)

// Compile-time interface check.
var _ platform.Entropy = (*SimEntropy)(nil)

// SimEntropy implements platform.Entropy using crypto/rand.
type SimEntropy struct{}

// Fill fills buf with cryptographic-quality random bytes.
func (e *SimEntropy) Fill(buf []byte) error {
	_, err := rand.Read(buf)
	return err
}
