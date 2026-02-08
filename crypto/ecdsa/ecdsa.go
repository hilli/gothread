// Package ecdsa provides ECDSA P-256 key generation, signing, and verification
// matching OpenThread's Ecdsa::P256 class.
//
// Reference: openthread/src/core/crypto/ecdsa.hpp
package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
)

const (
	// MpiSize is the size of a P-256 field element in bytes.
	MpiSize = 32
	// PublicKeySize is the size of an uncompressed public key (x || y).
	PublicKeySize = 64
	// SignatureSize is the size of an ECDSA signature (r || s).
	SignatureSize = 64
)

// PublicKey is a 64-byte uncompressed P-256 public key (x || y).
type PublicKey [PublicKeySize]byte

// Signature is a 64-byte ECDSA signature (r || s).
type Signature [SignatureSize]byte

// KeyPair holds an ECDSA P-256 key pair.
type KeyPair struct {
	key *ecdsa.PrivateKey
}

// GenerateKeyPair generates a new random P-256 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{key: key}, nil
}

// NewKeyPairFromPrivateKey creates a KeyPair from an existing *ecdsa.PrivateKey.
// The key must be on the P-256 curve.
func NewKeyPairFromPrivateKey(key *ecdsa.PrivateKey) (*KeyPair, error) {
	if key.Curve != elliptic.P256() {
		return nil, errors.New("ecdsa: key is not on P-256 curve")
	}
	return &KeyPair{key: key}, nil
}

// GetPublicKey returns the public key from the key pair.
func (kp *KeyPair) GetPublicKey() PublicKey {
	var pk PublicKey
	xBytes := kp.key.X.Bytes()
	yBytes := kp.key.Y.Bytes()
	// Pad to 32 bytes each (big-endian, left-padded with zeros).
	copy(pk[MpiSize-len(xBytes):MpiSize], xBytes)
	copy(pk[MpiSize+MpiSize-len(yBytes):], yBytes)
	return pk
}

// Sign signs a SHA-256 hash (must be 32 bytes) and returns the signature.
func (kp *KeyPair) Sign(hash [32]byte) (Signature, error) {
	r, s, err := ecdsa.Sign(rand.Reader, kp.key, hash[:])
	if err != nil {
		return Signature{}, err
	}
	var sig Signature
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[MpiSize-len(rBytes):MpiSize], rBytes)
	copy(sig[MpiSize+MpiSize-len(sBytes):], sBytes)
	return sig, nil
}

// Verify verifies a signature against a SHA-256 hash using this public key.
// Returns nil on success, an error if verification fails.
func (pk *PublicKey) Verify(hash [32]byte, sig Signature) error {
	x := new(big.Int).SetBytes(pk[:MpiSize])
	y := new(big.Int).SetBytes(pk[MpiSize:])

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	r := new(big.Int).SetBytes(sig[:MpiSize])
	s := new(big.Int).SetBytes(sig[MpiSize:])

	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return errors.New("ecdsa: signature verification failed")
	}
	return nil
}
