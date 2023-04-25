/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec"

	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
)

// CryptoSigner defines signer based on crypto.
type CryptoSigner struct {
	PubKeyBytes []byte
	PubKey      interface{}

	crypto cryptoapi.Crypto
	kh     interface{}
	kid    string
}

// Sign will sign document and return signature.
func (s *CryptoSigner) Sign(msg []byte) ([]byte, error) {
	return s.crypto.Sign(msg, s.kh)
}

// PublicKey returns a public key object (e.g. ed25519.VerificationMethod or *ecdsa.PublicKey).
func (s *CryptoSigner) PublicKey() interface{} {
	return s.PubKey
}

// KID returns key id.
func (s *CryptoSigner) KID() string {
	return s.kid
}

// PublicKeyBytes returns bytes of the public key.
func (s *CryptoSigner) PublicKeyBytes() []byte {
	return s.PubKeyBytes
}

// Alg returns alg.
func (s *CryptoSigner) Alg() string {
	switch pubKey := s.PubKey.(type) {
	case
		*ecdsa.PublicKey:
		switch pubKey.Curve {
		case elliptic.P256():
			return p256Alg
		case elliptic.P384():
			return p384Alg
		case elliptic.P521():
			return p521Alg
		case btcec.S256():
			return secp256Alg
		}
	case ed25519.PublicKey:
		return alg
	}

	return ""
}

// NewCryptoSigner creates a new CryptoSigner.
func NewCryptoSigner(crypto cryptoapi.Crypto, kms kmsapi.KeyManager, keyType kmsapi.KeyType) (*CryptoSigner, error) {
	kid, kh, err := kms.Create(keyType)
	if err != nil {
		return nil, err
	}

	pubKeyBytes, _, err := kms.ExportPubKeyBytes(kid)
	if err != nil {
		return nil, err
	}

	pubKey, err := getPublicKey(keyType, pubKeyBytes)
	if err != nil {
		return nil, err
	}

	return &CryptoSigner{
		kid:         kid,
		crypto:      crypto,
		kh:          kh,
		PubKey:      pubKey,
		PubKeyBytes: pubKeyBytes,
	}, nil
}

func getPublicKey(keyType kmsapi.KeyType, pubKeyBytes []byte) (interface{}, error) {
	switch keyType {
	case kmsapi.ECDSAP256TypeDER, kmsapi.ECDSAP384TypeDER, kmsapi.ECDSAP521TypeDER:
		pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("parse ECDSA public key: %w", err)
		}

		ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("unexpected type of ecdsa public key")
		}

		return ecdsaPubKey, nil

	case kmsapi.ECDSAP256TypeIEEEP1363:
		x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes)

		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}, nil

	case kmsapi.ECDSAP384TypeIEEEP1363:
		x, y := elliptic.Unmarshal(elliptic.P384(), pubKeyBytes)

		return &ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     x,
			Y:     y,
		}, nil

	case kmsapi.ECDSAP521TypeIEEEP1363:
		x, y := elliptic.Unmarshal(elliptic.P521(), pubKeyBytes)

		return &ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     x,
			Y:     y,
		}, nil

	case kmsapi.ED25519Type:
		return ed25519.PublicKey(pubKeyBytes), nil

	default:
		return nil, errors.New("unsupported key type")
	}
}
