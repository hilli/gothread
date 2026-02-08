package pbkdf2

import (
	"crypto/aes"
	"crypto/cipher"
)

// AES-CMAC constants.
const (
	blockSize = 16   // AES block size in bytes.
	rb        = 0x87 // Constant Rb for GF(2^128) doubling.
)

// aesCmac computes AES-CMAC (RFC 4493) over data using the given 16-byte key.
func aesCmac(key, data []byte) [blockSize]byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("pbkdf2: invalid AES key: " + err.Error())
	}

	k1, k2 := generateSubkeys(block)

	n := len(data)
	nBlocks := (n + blockSize - 1) / blockSize
	if nBlocks == 0 {
		nBlocks = 1
	}

	lastBlockComplete := n > 0 && n%blockSize == 0

	// Process all blocks except the last through CBC-MAC.
	var x [blockSize]byte
	for i := 0; i < nBlocks-1; i++ {
		offset := i * blockSize
		xorBlock(&x, data[offset:offset+blockSize])
		block.Encrypt(x[:], x[:])
	}

	// Process the last block with the appropriate subkey.
	var lastBlock [blockSize]byte
	if lastBlockComplete {
		copy(lastBlock[:], data[(nBlocks-1)*blockSize:])
		xorBlock(&lastBlock, k1[:])
	} else {
		remaining := n - (nBlocks-1)*blockSize
		copy(lastBlock[:], data[(nBlocks-1)*blockSize:])
		lastBlock[remaining] = 0x80 // pad with 10*
		xorBlock(&lastBlock, k2[:])
	}

	xorBlock(&x, lastBlock[:])
	block.Encrypt(x[:], x[:])

	return x
}

// generateSubkeys derives CMAC subkeys K1 and K2 from the AES cipher.
func generateSubkeys(block cipher.Block) (k1, k2 [blockSize]byte) {
	var zero [blockSize]byte
	var l [blockSize]byte
	block.Encrypt(l[:], zero[:])

	k1 = shiftLeft(l)
	if l[0]&0x80 != 0 {
		k1[blockSize-1] ^= rb
	}

	k2 = shiftLeft(k1)
	if k1[0]&0x80 != 0 {
		k2[blockSize-1] ^= rb
	}

	return k1, k2
}

// shiftLeft shifts a 16-byte block left by 1 bit.
func shiftLeft(input [blockSize]byte) [blockSize]byte {
	var output [blockSize]byte
	for i := 0; i < blockSize; i++ {
		output[i] = input[i] << 1
		if i+1 < blockSize && input[i+1]&0x80 != 0 {
			output[i] |= 0x01
		}
	}
	return output
}

// xorBlock XORs src into dst in-place.
func xorBlock(dst *[blockSize]byte, src []byte) {
	for i := 0; i < blockSize; i++ {
		dst[i] ^= src[i]
	}
}

// aesCmacPrf128 computes AES-CMAC-PRF-128 (RFC 4615).
//
// If the key is not exactly 16 bytes, it is first processed through AES-CMAC
// with a zero key to derive a 16-byte key.
func aesCmacPrf128(key, data []byte) [blockSize]byte {
	var derivedKey [blockSize]byte
	if len(key) != blockSize {
		var zeroKey [blockSize]byte
		derivedKey = aesCmac(zeroKey[:], key)
	} else {
		copy(derivedKey[:], key)
	}
	return aesCmac(derivedKey[:], data)
}
