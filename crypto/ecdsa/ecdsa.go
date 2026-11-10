// Package ecdsa provides ECDSA P-256 key generation, signing, and verification
// matching OpenThread's Ecdsa::P256 class.
//
// Reference: openthread/src/core/crypto/ecdsa.hpp
package ecdsa

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
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

// GenerateKeyPairWithReader uses only the supplied entropy source. Rejection
// sampling is bounded so a broken source cannot loop forever. Production readers
// must provide cryptographic-quality independent bytes; success cannot prove
// that physical precondition.
func GenerateKeyPairWithReader(reader io.Reader) (*KeyPair, error) {
	if reader == nil {
		return nil, errors.New("ecdsa: missing entropy reader")
	}
	var scalar [MpiSize]byte
	for range 128 {
		if _, err := io.ReadFull(reader, scalar[:]); err != nil {
			return nil, err
		}
		key, err := NewKeyPairFromScalar(scalar[:])
		if err == nil {
			return key, nil
		}
	}
	return nil, errors.New("ecdsa: invalid entropy samples")
}

// NewKeyPairFromScalar validates and imports the canonical 32-byte P-256 secret.
func NewKeyPairFromScalar(scalar []byte) (*KeyPair, error) {
	if len(scalar) != MpiSize {
		return nil, errors.New("ecdsa: invalid private scalar length")
	}
	private, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		return nil, errors.New("ecdsa: invalid private scalar")
	}
	public := private.PublicKey().Bytes()
	return &KeyPair{key: &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(),
			X: new(big.Int).SetBytes(public[1:33]), Y: new(big.Int).SetBytes(public[33:])},
		D: new(big.Int).SetBytes(scalar),
	}}, nil
}

// PrivateScalar exports secret bytes for an access-controlled durable backend.
// Callers must never log the returned value or expose it as a status field.
func (kp *KeyPair) PrivateScalar() [MpiSize]byte {
	var scalar [MpiSize]byte
	kp.key.D.FillBytes(scalar[:])
	return scalar
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
	return kp.SignWithReader(hash, rand.Reader)
}

// SignWithReader signs using the caller's qualified entropy source, without
// replacing global crypto/rand state. Reader errors are returned unchanged.
func (kp *KeyPair) SignWithReader(hash [32]byte, reader io.Reader) (Signature, error) {
	if reader == nil {
		return Signature{}, errors.New("ecdsa: missing entropy reader")
	}
	r, s, err := ecdsa.Sign(reader, kp.key, hash[:])
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
