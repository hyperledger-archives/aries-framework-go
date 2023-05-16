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

	"github.com/btcsuite/btcd/btcec"
	hybrid "github.com/google/tink/go/hybrid/subtle"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/util/cryptoutil"

	"github.com/hyperledger/aries-framework-go/spi/kms"

	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
)

var errInvalidKeyType = errors.New("key type is not supported")

// CreateKID creates a KID value based on the marshalled keyBytes of type kt. This function should be called for
// asymmetric public keys only (ECDSA DER or IEEE-P1363, ED25519, X25519, BLS12381G2).
// returns:
//   - base64 raw (no padding) URL encoded KID
//   - error in case of error
//
//nolint:gocyclo
func CreateKID(keyBytes []byte, kt kms.KeyType) (string, error) {
	if len(keyBytes) == 0 {
		return "", errors.New("createKID: empty key")
	}

	switch kt {
	case kms.X25519ECDHKWType: // X25519 JWK is not supported by go jose, manually build it and build its resulting KID.
		x25519KID, err := createX25519KID(keyBytes)
		if err != nil {
			return "", fmt.Errorf("createKID: %w", err)
		}

		return x25519KID, nil
	case kms.BLS12381G2Type: // BBS+ as JWK thumbprint.
		bbsKID, err := createBLS12381G2KID(keyBytes)
		if err != nil {
			return "", fmt.Errorf("createKID: %w", err)
		}

		return bbsKID, nil
	case kms.ECDSASecp256k1TypeDER, kms.ECDSASecp256k1TypeIEEEP1363:
		secp256k1KID, err := secp256k1Thumbprint(keyBytes, kt)
		if err != nil {
			return "", fmt.Errorf("createKID: %w", err)
		}

		return secp256k1KID, nil
	}

	j, err := BuildJWK(keyBytes, kt)
	if err != nil {
		return "", fmt.Errorf("createKID: failed to build jwk: %w", err)
	}

	tp, err := j.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("createKID: failed to get jwk Thumbprint: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(tp), nil
}

func secp256k1Thumbprint(keyBytes []byte, kt kms.KeyType) (string, error) {
	switch kt {
	case kms.ECDSASecp256k1IEEEP1363:
	case kms.ECDSASecp256k1DER:
	default:
		return "", fmt.Errorf("secp256k1Thumbprint: invalid key type: %s", kt)
	}

	j, err := BuildJWK(keyBytes, kt)
	if err != nil {
		return "", fmt.Errorf("secp256k1Thumbprint: failed to build jwk: %w", err)
	}

	var input string

	switch key := j.Key.(type) {
	case *ecdsa.PublicKey:
		input, err = secp256k1ThumbprintInput(key.Curve, key.X, key.Y)
		if err != nil {
			return "", fmt.Errorf("secp256k1Thumbprint: failed to get public key thumbprint input: %w", err)
		}
	case *ecdsa.PrivateKey:
		input, err = secp256k1ThumbprintInput(key.Curve, key.X, key.Y)
		if err != nil {
			return "", fmt.Errorf("secp256k1Thumbprint: failed to get private key thumbprint input: %w", err)
		}
	default:
		return "", fmt.Errorf("secp256k1Thumbprint: unknown key type '%T'", key)
	}

	h := crypto.SHA256.New()
	_, _ = h.Write([]byte(input))

	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

func secp256k1ThumbprintInput(curve elliptic.Curve, x, y *big.Int) (string, error) {
	ecSecp256K1ThumbprintTemplate := `{"crv":"SECP256K1","kty":"EC","x":"%s","y":"%s"}`

	coordLength := curveSize(curve)

	if len(x.Bytes()) > coordLength || len(y.Bytes()) > coordLength {
		return "", errors.New("invalid elliptic secp256k1 key (too large)")
	}

	return fmt.Sprintf(ecSecp256K1ThumbprintTemplate,
		newFixedSizeBuffer(x.Bytes(), coordLength).base64(),
		newFixedSizeBuffer(y.Bytes(), coordLength).base64()), nil
}

// byteBuffer represents a slice of bytes that can be serialized to url-safe base64.
type byteBuffer struct {
	data []byte
}

func (b *byteBuffer) base64() string {
	return base64.RawURLEncoding.EncodeToString(b.data)
}

func newBuffer(data []byte) *byteBuffer {
	if data == nil {
		return nil
	}

	return &byteBuffer{
		data: data,
	}
}

func newFixedSizeBuffer(data []byte, length int) *byteBuffer {
	if len(data) > length {
		panic("newFixedSizeBuffer: invalid call to newFixedSizeBuffer (len(data) > length)")
	}

	pad := make([]byte, length-len(data))

	return newBuffer(append(pad, data...))
}

// Get size of curve in bytes.
func curveSize(crv elliptic.Curve) int {
	bits := crv.Params().BitSize
	byteSize := 8

	div := bits / byteSize
	mod := bits % byteSize

	if mod == 0 {
		return div
	}

	return div + 1
}

// BuildJWK builds a go jose JWK from keyBytes with key type kt.
func BuildJWK(keyBytes []byte, kt kms.KeyType) (*jwk.JWK, error) { //nolint: gocyclo
	var (
		j   *jwk.JWK
		err error
	)

	switch kt {
	case kms.ECDSAP256TypeDER, kms.ECDSAP384TypeDER, kms.ECDSAP521TypeDER, kms.ECDSASecp256k1DER:
		j, err = generateJWKFromDERECDSA(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("buildJWK: failed to build JWK from ecdsa DER key: %w", err)
		}
	case kms.ED25519Type:
		j, err = jwksupport.JWKFromKey(ed25519.PublicKey(keyBytes))
		if err != nil {
			return nil, fmt.Errorf("buildJWK: failed to build JWK from ed25519 key: %w", err)
		}
	case kms.ECDSAP256TypeIEEEP1363, kms.ECDSAP384TypeIEEEP1363, kms.ECDSAP521TypeIEEEP1363, kms.ECDSASecp256k1IEEEP1363:
		c := getCurveByKMSKeyType(kt)
		x, y := elliptic.Unmarshal(c, keyBytes)

		pubKey := &ecdsa.PublicKey{
			Curve: c,
			X:     x,
			Y:     y,
		}

		j, err = jwksupport.JWKFromKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("buildJWK: failed to build JWK from ecdsa key in IEEE1363 format: %w", err)
		}
	case kms.NISTP256ECDHKWType, kms.NISTP384ECDHKWType, kms.NISTP521ECDHKWType:
		j, err = generateJWKFromECDH(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("buildJWK: failed to build JWK from ecdh key: %w", err)
		}
	case kms.X25519ECDHKWType:
		pubKey, err := unmarshalECDHKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("buildJWK: failed to unmarshal public key from X25519 key: %w", err)
		}

		j, err = jwksupport.JWKFromX25519Key(pubKey.X)
		if err != nil {
			return nil, fmt.Errorf("buildJWK: failed to build JWK from X25519 key: %w", err)
		}
	default:
		return nil, fmt.Errorf("buildJWK: %w: '%s'", errInvalidKeyType, kt)
	}

	return j, nil
}

func generateJWKFromDERECDSA(keyBytes []byte) (*jwk.JWK, error) {
	pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("generateJWKFromDERECDSA: failed to parse ecdsa key in DER format: %w", err)
	}

	return jwksupport.JWKFromKey(pubKey)
}

func generateJWKFromECDH(keyBytes []byte) (*jwk.JWK, error) {
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

	return jwksupport.JWKFromKey(pubKey)
}

func getCurveByKMSKeyType(kt kms.KeyType) elliptic.Curve {
	switch kt {
	case kms.ECDSAP256TypeIEEEP1363:
		return elliptic.P256()
	case kms.ECDSAP384TypeIEEEP1363:
		return elliptic.P384()
	case kms.ECDSAP521TypeIEEEP1363:
		return elliptic.P521()
	case kms.ECDSASecp256k1TypeIEEEP1363:
		return btcec.S256()
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

	j, err := buildX25519JWK(compositeKey.X)
	if err != nil {
		return "", fmt.Errorf("createX25519KID: %w", err)
	}

	thumbprint := sha256Sum(j)

	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func buildX25519JWK(keyBytes []byte) (string, error) {
	const x25519ThumbprintTemplate = `{"crv":"X25519","kty":"OKP","x":"%s"}`

	lenKey := len(keyBytes)
	if lenKey > cryptoutil.Curve25519KeySize {
		return "", errors.New("buildX25519JWK: invalid ECDH X25519 key")
	}

	pad := make([]byte, cryptoutil.Curve25519KeySize-lenKey)
	x25519RawKey := append(pad, keyBytes...)

	j := fmt.Sprintf(x25519ThumbprintTemplate, base64.RawURLEncoding.EncodeToString(x25519RawKey))

	return j, nil
}

func createBLS12381G2KID(keyBytes []byte) (string, error) {
	const (
		bls12381g2ThumbprintTemplate = `{"crv":"Bls12381g2","kty":"OKP","x":"%s"}`
		// Default BLS 12-381 public key length in G2 field.
		bls12381G2PublicKeyLen = 96
	)

	lenKey := len(keyBytes)

	if lenKey > bls12381G2PublicKeyLen {
		return "", errors.New("invalid BBS+ key")
	}

	pad := make([]byte, bls12381G2PublicKeyLen-lenKey)
	bbsRawKey := append(pad, keyBytes...)

	j := fmt.Sprintf(bls12381g2ThumbprintTemplate, base64.RawURLEncoding.EncodeToString(bbsRawKey))

	thumbprint := sha256Sum(j)

	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func sha256Sum(j string) []byte {
	h := crypto.SHA256.New()
	_, _ = h.Write([]byte(j)) // SHA256 digest returns empty error on Write()

	return h.Sum(nil)
}
