// Package pbkdf2 provides PBKDF2 key derivation using AES-CMAC-PRF-128
// as the pseudorandom function, as used in Thread's MeshCoP for PSKc derivation.
//
// Reference: openthread/src/core/crypto/pbkdf2_cmac.cpp (platform implementation)
package pbkdf2

import (
	"encoding/binary"
	"errors"
)

// prfLen is the output length of AES-CMAC-PRF-128 in bytes.
const prfLen = 16

// GenerateKey derives a key using PBKDF2 with AES-CMAC-PRF-128 as the PRF.
//
// password is the input passphrase.
// salt is the salt value.
// iterations is the iteration count. Following OpenThread's implementation,
// this value is halved internally, so it must be even and positive.
// keyLen is the desired output key length in bytes.
func GenerateKey(password, salt []byte, iterations, keyLen int) ([]byte, error) {
	if iterations <= 0 || iterations%2 != 0 {
		return nil, errors.New("pbkdf2: iteration count must be a positive even number")
	}
	if keyLen <= 0 {
		return nil, errors.New("pbkdf2: key length must be positive")
	}

	// OpenThread halves the iteration count internally.
	iter := iterations / 2

	numBlocks := (keyLen + prfLen - 1) / prfLen
	dk := make([]byte, 0, numBlocks*prfLen)

	for blockIdx := 1; blockIdx <= numBlocks; blockIdx++ {
		block := pbkdf2Block(password, salt, iter, blockIdx)
		dk = append(dk, block[:]...)
	}

	return dk[:keyLen], nil
}

// pbkdf2Block computes F(Password, Salt, c, i) = U1 ^ U2 ^ ... ^ Uc.
func pbkdf2Block(password, salt []byte, iterations, blockIndex int) [prfLen]byte {
	// U1 = PRF(Password, Salt || INT(i))
	// INT(i) is a 4-byte big-endian encoding of i.
	saltI := make([]byte, len(salt)+4)
	copy(saltI, salt)
	binary.BigEndian.PutUint32(saltI[len(salt):], uint32(blockIndex))

	u := aesCmacPrf128(password, saltI)
	result := u

	// U2 ... Uc
	for j := 1; j < iterations; j++ {
		u = aesCmacPrf128(password, u[:])
		for k := 0; k < prfLen; k++ {
			result[k] ^= u[k]
		}
	}

	return result
}
