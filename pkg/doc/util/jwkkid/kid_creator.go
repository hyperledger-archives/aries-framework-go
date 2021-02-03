/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwkkid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	hybrid "github.com/google/tink/go/hybrid/subtle"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

var errInvalidKeyType = errors.New("key type is not supported")

// CreateKID creates a KID value based on the marshalled keyBytes of type kt. This function should be called for
// asymmetric public keys only (ECDSA DER or IEEE1363, ED25519).
// returns:
//  - base64 raw (no padding) URL encoded KID
//  - error in case of error
func CreateKID(keyBytes []byte, kt kms.KeyType) (string, error) {
	// X25519 JWK is not supported by go jose, manually build it and build its resulting KID.
	if kt == kms.X25519ECDHKWType {
		x25519KID, err := createX25519KID(keyBytes)
		if err != nil {
			return "", fmt.Errorf("createKID: %w", err)
		}

		return x25519KID, nil
	}

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
		c := getCurveByKMSKeyType(kt)
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
	case kms.NISTP256ECDHKWType, kms.NISTP384ECDHKWType, kms.NISTP521ECDHKWType:
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
	compositeKey, err := unmarshalECDHKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("generateJWKFromECDH: %w", err)
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

func getCurveByKMSKeyType(kt kms.KeyType) elliptic.Curve {
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

func unmarshalECDHKey(keyBytes []byte) (*cryptoapi.PublicKey, error) {
	compositeKey := &cryptoapi.PublicKey{}

	err := json.Unmarshal(keyBytes, compositeKey)
	if err != nil {
		return nil, fmt.Errorf("unmarshalECDHKey: failed to unmarshal ECDH key: %w", err)
	}

	return compositeKey, nil
}

func createX25519KID(marshalledKey []byte) (string, error) {
	compositeKey, err := unmarshalECDHKey(marshalledKey)
	if err != nil {
		return "", fmt.Errorf("createX25519KID: %w", err)
	}

	jwk, err := buildX25519JWK(compositeKey.X)
	if err != nil {
		return "", fmt.Errorf("createX25519KID: %w", err)
	}

	thumbprint := thumbprintX25519(jwk)

	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func buildX25519JWK(keyBytes []byte) (string, error) {
	const x25519ThumbprintTemplate = `{"crv":"X25519","kty":"OKP","x":"%s"}`

	if len(keyBytes) > cryptoutil.Curve25519KeySize {
		return "", errors.New("buildX25519JWK: invalid ECDH X25519 key")
	}

	pad := make([]byte, cryptoutil.Curve25519KeySize-len(keyBytes))
	x25519RawKey := append(pad, keyBytes...)

	jwk := fmt.Sprintf(x25519ThumbprintTemplate, base64.RawURLEncoding.EncodeToString(x25519RawKey))

	return jwk, nil
}

func thumbprintX25519(jwk string) []byte {
	h := crypto.SHA256.New()
	_, _ = h.Write([]byte(jwk)) // nolint: errcheck // SHA256 digest returns empty error on Write()

	return h.Sum(nil)
}
