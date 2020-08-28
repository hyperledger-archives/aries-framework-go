/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	hybrid "github.com/google/tink/go/hybrid/subtle"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// CreateKID creates a KID value based on the marshalled keyBytes of type kt. This function should be called for
// asymmetric public keys only (ECDSA DER or IEEE1363, ED25519).
// returns:
//  - base64 raw (no padding) URL encoded KID
//  - error in case of error
func CreateKID(keyBytes []byte, kt kms.KeyType) (string, error) {
	jwk, err := buildJWK(keyBytes, kt)
	if err != nil {
		return "", fmt.Errorf("createKID: failed to build jwk: %w", err)
	}

	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("createKID: failed to get jwk Thumbprint: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(tp), nil
}

func buildJWK(keyBytes []byte, kt kms.KeyType) (*jose.JWK, error) {
	var (
		jwk *jose.JWK
		err error
	)

	switch kt {
	case kms.ECDSAP256TypeDER, kms.ECDSAP384TypeDER, kms.ECDSAP521TypeDER:
		jwk, err = generateJWKFromDERECDSA(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("buildJWK: failed to build JWK from ecdsa DER key: %w", err)
		}
	case kms.ED25519Type:
		jwk, err = jose.JWKFromPublicKey(ed25519.PublicKey(keyBytes))
		if err != nil {
			return nil, fmt.Errorf("buildJWK: failed to build JWK from ed25519 key: %w", err)
		}
	case kms.ECDSAP256TypeIEEEP1363, kms.ECDSAP384TypeIEEEP1363, kms.ECDSAP521TypeIEEEP1363:
		c := getCurve(kt)
		x, y := elliptic.Unmarshal(c, keyBytes)

		pubKey := &ecdsa.PublicKey{
			Curve: c,
			X:     x,
			Y:     y,
		}

		jwk, err = jose.JWKFromPublicKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("buildJWK: failed to build JWK from ecdsa key in IEEE1363 format: %w", err)
		}
	case kms.ECDHES256AES256GCMType, kms.ECDHES384AES256GCMType, kms.ECDHES521AES256GCMType,
		kms.ECDH1PU256AES256GCMType, kms.ECDH1PU384AES256GCMType, kms.ECDH1PU521AES256GCMType:
		jwk, err = generateJWKFromECDH(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("buildJWK: failed to build JWK from ecdh key: %w", err)
		}
	default:
		return nil, fmt.Errorf("buildJWK: %w: '%s'", errInvalidKeyType, kt)
	}

	return jwk, nil
}

func generateJWKFromDERECDSA(keyBytes []byte) (*jose.JWK, error) {
	pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("generateJWKFromDERECDSA: failed to parse ecdsa key in DER format: %w", err)
	}

	return jose.JWKFromPublicKey(pubKey)
}

func generateJWKFromECDH(keyBytes []byte) (*jose.JWK, error) {
	compositeKey := &composite.PublicKey{}

	err := json.Unmarshal(keyBytes, compositeKey)
	if err != nil {
		return nil, fmt.Errorf("generateJWKFromECDH: failed to unmarshal ECDH key: %w", err)
	}

	c, err := hybrid.GetCurve(compositeKey.Curve)
	if err != nil {
		return nil, fmt.Errorf("generateJWKFromECDH: failed to get Curve for ECDH key: %w", err)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: c,
		X:     new(big.Int).SetBytes(compositeKey.X),
		Y:     new(big.Int).SetBytes(compositeKey.Y),
	}

	return jose.JWKFromPublicKey(pubKey)
}

func getCurve(kt kms.KeyType) elliptic.Curve {
	switch kt {
	case kms.ECDSAP256TypeIEEEP1363:
		return elliptic.P256()
	case kms.ECDSAP384TypeIEEEP1363:
		return elliptic.P384()
	case kms.ECDSAP521TypeIEEEP1363:
		return elliptic.P521()
	}

	// should never be called but added for linting
	return elliptic.P256()
}
