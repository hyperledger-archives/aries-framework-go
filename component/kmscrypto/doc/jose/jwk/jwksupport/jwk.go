/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwksupport

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/go-jose/go-jose/v3"

	"github.com/hyperledger/aries-framework-go/spi/kms"

	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
)

const (
	ecKty          = "EC"
	okpKty         = "OKP"
	x25519Crv      = "X25519"
	bls12381G2Crv  = "BLS12381_G2"
	bls12381G2Size = 96
)

// JWKFromKey creates a JWK from an opaque key struct.
// It's e.g. *ecdsa.PublicKey, *ecdsa.PrivateKey, ed25519.VerificationMethod, *bbs12381g2pub.PrivateKey or
// *bbs12381g2pub.PublicKey.
func JWKFromKey(opaqueKey interface{}) (*jwk.JWK, error) {
	key := &jwk.JWK{
		JSONWebKey: jose.JSONWebKey{
			Key: opaqueKey,
		},
	}

	// marshal/unmarshal to get all JWK's fields other than Key filled.
	keyBytes, err := key.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("create JWK: %w", err)
	}

	err = key.UnmarshalJSON(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("create JWK: %w", err)
	}

	return key, nil
}

// JWKFromX25519Key is similar to JWKFromKey but is specific to X25519 keys when using a public key as raw []byte.
// This builder function presets the curve and key type in the JWK.
// Using JWKFromKey for X25519 raw keys will not have these fields set and will not provide the right JWK output.
func JWKFromX25519Key(pubKey []byte) (*jwk.JWK, error) {
	key := &jwk.JWK{
		JSONWebKey: jose.JSONWebKey{
			Key: pubKey,
		},
		Crv: x25519Crv,
		Kty: okpKty,
	}

	// marshal/unmarshal to get all JWK's fields other than Key filled.
	keyBytes, err := key.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("create JWK: %w", err)
	}

	err = key.UnmarshalJSON(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("create JWK: %w", err)
	}

	return key, nil
}

// PubKeyBytesToJWK converts marshalled bytes of keyType into JWK.
func PubKeyBytesToJWK(bytes []byte, keyType kms.KeyType) (*jwk.JWK, error) { // nolint:gocyclo
	switch keyType {
	case kms.ED25519Type:
		return JWKFromKey(ed25519.PublicKey(bytes))
	case kms.BLS12381G2Type:
		bbsKey, err := bbs12381g2pub.UnmarshalPublicKey(bytes)
		if err != nil {
			return nil, err
		}

		return JWKFromKey(bbsKey)
	case kms.ECDSAP256TypeIEEEP1363, kms.ECDSAP384TypeIEEEP1363, kms.ECDSAP521TypeIEEEP1363:
		crv := getECDSACurve(keyType)
		x, y := elliptic.Unmarshal(crv, bytes)

		return JWKFromKey(&ecdsa.PublicKey{Curve: crv, X: x, Y: y})
	case kms.ECDSAP256TypeDER, kms.ECDSAP384TypeDER, kms.ECDSAP521TypeDER:
		pubKey, err := x509.ParsePKIXPublicKey(bytes)
		if err != nil {
			return nil, err
		}

		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid EC key")
		}

		return JWKFromKey(ecKey)
	case kms.NISTP256ECDHKWType, kms.NISTP384ECDHKWType, kms.NISTP521ECDHKWType:
		crv := getECDSACurve(keyType)
		pubKey := &cryptoapi.PublicKey{}

		err := json.Unmarshal(bytes, pubKey)
		if err != nil {
			return nil, err
		}

		ecdsaKey := &ecdsa.PublicKey{
			Curve: crv,
			X:     new(big.Int).SetBytes(pubKey.X),
			Y:     new(big.Int).SetBytes(pubKey.Y),
		}

		return JWKFromKey(ecdsaKey)
	case kms.X25519ECDHKWType:
		return JWKFromX25519Key(bytes)
	default:
		return nil, fmt.Errorf("convertPubKeyJWK: invalid key type: %s", keyType)
	}
}

func getECDSACurve(keyType kms.KeyType) elliptic.Curve {
	switch keyType {
	case kms.ECDSAP256TypeIEEEP1363, kms.ECDSAP256TypeDER, kms.NISTP256ECDHKWType:
		return elliptic.P256()
	case kms.ECDSAP384TypeIEEEP1363, kms.ECDSAP384TypeDER, kms.NISTP384ECDHKWType:
		return elliptic.P384()
	case kms.ECDSAP521TypeIEEEP1363, kms.ECDSAP521TypeDER, kms.NISTP521ECDHKWType:
		return elliptic.P521()
	}

	return nil
}

// PublicKeyFromJWK builds a cryptoapi.PublicKey from jwkKey.
func PublicKeyFromJWK(jwkKey *jwk.JWK) (*cryptoapi.PublicKey, error) {
	if jwkKey != nil {
		pubKey := &cryptoapi.PublicKey{
			KID:   jwkKey.KeyID,
			Curve: jwkKey.Crv,
			Type:  jwkKey.Kty,
		}

		switch key := jwkKey.Key.(type) {
		case *ecdsa.PublicKey:
			pubKey.X = key.X.Bytes()
			pubKey.Y = key.Y.Bytes()
		case *ecdsa.PrivateKey:
			pubKey.X = key.X.Bytes()
			pubKey.Y = key.Y.Bytes()
		case *bbs12381g2pub.PublicKey:
			bbsKey, _ := key.Marshal() //nolint:errcheck // bbs marshal public key does not return any error

			pubKey.X = bbsKey
		case *bbs12381g2pub.PrivateKey:
			bbsKey, _ := key.PublicKey().Marshal() //nolint:errcheck // bbs marshal public key does not return any error

			pubKey.X = bbsKey
		case ed25519.PublicKey:
			pubKey.X = key
		case ed25519.PrivateKey:
			var ok bool

			pubEdKey, ok := key.Public().(ed25519.PublicKey)
			if !ok {
				return nil, errors.New("publicKeyFromJWK: invalid 25519 private key")
			}

			pubKey.X = pubEdKey
		default:
			return nil, fmt.Errorf("publicKeyFromJWK: unsupported jwk key type %T", jwkKey.Key)
		}

		return pubKey, nil
	}

	return nil, errors.New("publicKeyFromJWK: jwk is empty")
}
