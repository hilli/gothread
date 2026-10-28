// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"

	csettings "github.com/hilli/gothread/common/settings"
	"github.com/hilli/gothread/crypto/ecdsa"
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/platform"
)

type platformEntropyReader struct{ entropy platform.Entropy }

func (r platformEntropyReader) Read(data []byte) (int, error) {
	if err := r.entropy.Fill(data); err != nil {
		return 0, err
	}
	return len(data), nil
}

// One versioned record occupies the already established SRP signing-key slot.
// Atomicity, durability, access control, and entropy quality are backend
// preconditions. Never log record bytes or regenerate an invalid record.
func (inst *Instance) loadSRPKey() (*ecdsa.KeyPair, error) {
	if inst.stackSettings == nil || inst.entropy == nil {
		return nil, goterrors.ErrInvalidState
	}
	if inst.srpKeyErr != nil {
		return nil, inst.srpKeyErr
	}
	data, err := inst.stackSettings.ReadSrpEcdsaKey()
	if err == nil {
		if len(data) != 41 || string(data[:4]) != "SRPK" || data[4] != 1 ||
			crc32.ChecksumIEEE(data[:37]) != binary.BigEndian.Uint32(data[37:]) {
			return nil, fmt.Errorf("instance: invalid SRP key record: %w", goterrors.ErrParse)
		}
		key, keyErr := ecdsa.NewKeyPairFromScalar(data[5:37])
		if keyErr != nil {
			return nil, fmt.Errorf("instance: invalid SRP key scalar: %w", goterrors.ErrParse)
		}
		return key, nil
	}
	if !errors.Is(err, csettings.ErrNotFound) {
		return nil, fmt.Errorf("instance: read SRP key: %w", err)
	}
	key, err := ecdsa.GenerateKeyPairWithReader(platformEntropyReader{inst.entropy})
	if err != nil {
		return nil, fmt.Errorf("instance: create SRP key: %w", err)
	}
	scalar := key.PrivateScalar()
	var record [41]byte
	copy(record[:4], "SRPK")
	record[4] = 1
	copy(record[5:37], scalar[:])
	binary.BigEndian.PutUint32(record[37:], crc32.ChecksumIEEE(record[:37]))
	if err := inst.stackSettings.WriteSrpEcdsaKey(record[:]); err != nil {
		inst.srpKeyErr = fmt.Errorf("instance: persist SRP key (fresh Instance must reopen): %w", err)
		return nil, inst.srpKeyErr
	}
	return key, nil
}
