/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"

	"github.com/btcsuite/btcd/btcec"
)

// NewECDSAP256Signer creates a new ECDSA P256 signer with generated key.
func NewECDSAP256Signer() (*ECDSASigner, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECDSASigner{privateKey: privKey, PublicKey: &privKey.PublicKey, hash: crypto.SHA256}, nil
}

// GetECDSAP256Signer creates a new ECDSA P256 signer with passed ECDSA P256 private key.
func GetECDSAP256Signer(privKey *ecdsa.PrivateKey) *ECDSASigner {
	return &ECDSASigner{privateKey: privKey, PublicKey: &privKey.PublicKey, hash: crypto.SHA256}
}

// NewECDSAP384Signer creates a new ECDSA P384 signer with generated key.
func NewECDSAP384Signer() (*ECDSASigner, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECDSASigner{privateKey: privKey, PublicKey: &privKey.PublicKey, hash: crypto.SHA384}, nil
}

// GetECDSAP384Signer creates a new ECDSA P384 signer with passed ECDSA P384 private key.
func GetECDSAP384Signer(privKey *ecdsa.PrivateKey) *ECDSASigner {
	return &ECDSASigner{privateKey: privKey, PublicKey: &privKey.PublicKey, hash: crypto.SHA384}
}

// NewECDSAP521Signer creates a new ECDSA P521 signer with generated key.
func NewECDSAP521Signer() (*ECDSASigner, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECDSASigner{privateKey: privKey, PublicKey: &privKey.PublicKey, hash: crypto.SHA512}, nil
}

// GetECDSAP521Signer creates a new ECDSA P521 signer with passed ECDSA P521 private key.
func GetECDSAP521Signer(privKey *ecdsa.PrivateKey) *ECDSASigner {
	return &ECDSASigner{privateKey: privKey, PublicKey: &privKey.PublicKey, hash: crypto.SHA512}
}

// NewECDSASecp256k1Signer creates a new ECDSA Secp256k1 signer with generated key.
func NewECDSASecp256k1Signer() (*ECDSASigner, error) {
	privKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECDSASigner{privateKey: privKey, PublicKey: &privKey.PublicKey, hash: crypto.SHA256}, nil
}

// GetECDSASecp256k1Signer creates a new ECDSA Secp256k1 signer with passed ECDSA Secp256k1 private key.
func GetECDSASecp256k1Signer(privKey *ecdsa.PrivateKey) *ECDSASigner {
	return &ECDSASigner{privateKey: privKey, PublicKey: &privKey.PublicKey, hash: crypto.SHA256}
}

// NewECDSASigner creates a new ECDSA signer based on the input elliptic curve.
func NewECDSASigner(curve elliptic.Curve) (*ECDSASigner, error) {
	switch curve {
	case elliptic.P256():
		return NewECDSAP256Signer()

	case elliptic.P384():
		return NewECDSAP384Signer()

	case elliptic.P521():
		return NewECDSAP521Signer()

	case btcec.S256():
		return NewECDSASecp256k1Signer()

	default:
		return nil, errors.New("unsupported curve")
	}
}

// ECDSASigner makes ECDSA based signatures.
type ECDSASigner struct {
	privateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	hash       crypto.Hash
}

// Sign signs a message.
func (es *ECDSASigner) Sign(msg []byte) ([]byte, error) {
	return signEcdsa(msg, es.privateKey, es.hash)
}

//nolint:gomnd
func signEcdsa(msg []byte, privateKey *ecdsa.PrivateKey, hash crypto.Hash) ([]byte, error) {
	hasher := hash.New()
	_, _ = hasher.Write(msg) //nolint:errcheck
	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
	if err != nil {
		return nil, err
	}

	curveBits := privateKey.Curve.Params().BitSize

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	copyPadded := func(source []byte, size int) []byte {
		dest := make([]byte, size)
		copy(dest[size-len(source):], source)

		return dest
	}

	return append(copyPadded(r.Bytes(), keyBytes), copyPadded(s.Bytes(), keyBytes)...), nil
}
