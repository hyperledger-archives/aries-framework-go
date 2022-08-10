/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"

	"github.com/btcsuite/btcd/btcec"
)

const (
	p256Alg    = "ES256"
	p384Alg    = "ES384"
	p521Alg    = "ES521"
	secp256Alg = "ES256K"
)

// NewECDSAP256Signer creates a new ECDSA P256 signer with generated key.
func NewECDSAP256Signer() (*ECDSASigner, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return newECDSASigner(privKey, &privKey.PublicKey, crypto.SHA256, p256Alg), nil
}

// GetECDSAP256Signer creates a new ECDSA P256 signer with passed ECDSA P256 private key.
func GetECDSAP256Signer(privKey *ecdsa.PrivateKey) *ECDSASigner {
	return newECDSASigner(privKey, &privKey.PublicKey, crypto.SHA256, p256Alg)
}

// NewECDSAP384Signer creates a new ECDSA P384 signer with generated key.
func NewECDSAP384Signer() (*ECDSASigner, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return newECDSASigner(privKey, &privKey.PublicKey, crypto.SHA384, p384Alg), nil
}

// GetECDSAP384Signer creates a new ECDSA P384 signer with passed ECDSA P384 private key.
func GetECDSAP384Signer(privKey *ecdsa.PrivateKey) *ECDSASigner {
	return newECDSASigner(privKey, &privKey.PublicKey, crypto.SHA384, p384Alg)
}

// NewECDSAP521Signer creates a new ECDSA P521 signer with generated key.
func NewECDSAP521Signer() (*ECDSASigner, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return newECDSASigner(privKey, &privKey.PublicKey, crypto.SHA512, p521Alg), nil
}

// GetECDSAP521Signer creates a new ECDSA P521 signer with passed ECDSA P521 private key.
func GetECDSAP521Signer(privKey *ecdsa.PrivateKey) *ECDSASigner {
	return newECDSASigner(privKey, &privKey.PublicKey, crypto.SHA512, p521Alg)
}

// NewECDSASecp256k1Signer creates a new ECDSA Secp256k1 signer with generated key.
func NewECDSASecp256k1Signer() (*ECDSASigner, error) {
	privKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return newECDSASigner(privKey, &privKey.PublicKey, crypto.SHA256, secp256Alg), nil
}

// GetECDSASecp256k1Signer creates a new ECDSA Secp256k1 signer with passed ECDSA Secp256k1 private key.
func GetECDSASecp256k1Signer(privKey *ecdsa.PrivateKey) *ECDSASigner {
	return newECDSASigner(privKey, &privKey.PublicKey, crypto.SHA256, secp256Alg)
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

// GetECDSASigner creates a new ECDSA signer based on the input *ecdsa.PrivateKey.
func GetECDSASigner(privKey *ecdsa.PrivateKey) (*ECDSASigner, error) {
	switch privKey.Curve {
	case elliptic.P256():
		return GetECDSAP256Signer(privKey), nil
	case elliptic.P384():
		return GetECDSAP384Signer(privKey), nil
	case elliptic.P521():
		return GetECDSAP521Signer(privKey), nil
	case btcec.S256():
		return GetECDSASecp256k1Signer(privKey), nil
	default:
		return nil, errors.New("unsupported curve")
	}
}

// ECDSASigner makes ECDSA based signatures.
type ECDSASigner struct {
	privateKey  *ecdsa.PrivateKey
	PubKey      *ecdsa.PublicKey
	pubKeyBytes []byte
	hash        crypto.Hash
	alg         string
}

func newECDSASigner(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey, hash crypto.Hash, alg string) *ECDSASigner {
	return &ECDSASigner{
		privateKey:  privKey,
		PubKey:      pubKey,
		pubKeyBytes: elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y),
		hash:        hash,
		alg:         alg,
	}
}

// PublicKey returns a public key object (*ecdsa.PublicKey).
func (es *ECDSASigner) PublicKey() interface{} {
	return es.PubKey
}

// PublicKeyBytes returns bytes of the public key.
func (es *ECDSASigner) PublicKeyBytes() []byte {
	return es.pubKeyBytes
}

// Sign signs a message.
func (es *ECDSASigner) Sign(msg []byte) ([]byte, error) {
	return signEcdsa(msg, es.privateKey, es.hash)
}

// Alg return alg.
func (es *ECDSASigner) Alg() string {
	return es.alg
}

//nolint:gomnd
func signEcdsa(msg []byte, privateKey *ecdsa.PrivateKey, hash crypto.Hash) ([]byte, error) {
	hasher := hash.New()
	_, _ = hasher.Write(msg)
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
