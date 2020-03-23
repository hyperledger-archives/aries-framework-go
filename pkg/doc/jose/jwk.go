/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v2"
	"github.com/square/go-jose/v3"
	"golang.org/x/crypto/ed25519"
)

const (
	secp256k1Crv = "secp256k1"
	secp256k1Kty = "EC"
	bitsPerByte  = 8
)

// JWK (JSON Web Key) is a JSON data structure that represents a cryptographic key.
type JWK jose.JSONWebKey

// JWK gets JWK from JOSE headers.
func (h Headers) JWK() (*JWK, bool) {
	jwkRaw, ok := h[HeaderJSONWebKey]
	if !ok {
		return nil, false
	}

	var jwk JWK

	err := convertMapToValue(jwkRaw, &jwk)
	if err != nil {
		return nil, false
	}

	return &jwk, true
}

// jsonWebKey contains subset of json web key json properties
type jsonWebKey struct {
	Kty string      `json:"kty,omitempty"`
	Kid string      `json:"kid,omitempty"`
	Crv string      `json:"crv,omitempty"`
	X   *byteBuffer `json:"x,omitempty"`
	Y   *byteBuffer `json:"y,omitempty"`
}

// DecodePublicKey reads a public key from its JSON Web Key representation.
// TODO : to be part of jose.JWK [Issue#1513]
func DecodePublicKey(jwkBytes []byte) ([]byte, error) {
	key := &jsonWebKey{}

	err := json.Unmarshal(jwkBytes, key)
	if err != nil {
		return nil, fmt.Errorf("unable to read JWK, %w", err)
	}

	if strings.EqualFold(key.Kty, secp256k1Kty) && strings.EqualFold(key.Crv, secp256k1Crv) {
		//  if kty="EC" and Crv="secp256k1", then handle differently
		return btcPublicKey(key.X, key.Y)
	}

	jwk := jose.JSONWebKey{}

	// read key from its JSON representation.
	err = jwk.UnmarshalJSON(jwkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}

	// get public key bytes from jwk
	switch pubKey := jwk.Public().Key.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		pubKBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read public key: %w", err)
		}

		return pubKBytes, nil
	default:
		return nil, fmt.Errorf("unsupported public key type in kid '%s'", key.Kid)
	}
}

// return public key bytes using given(x,y) using curve=secp256k1
func btcPublicKey(xBuffer, yBuffer *byteBuffer) ([]byte, error) {
	curve := secp256k1.S256()

	if xBuffer == nil || yBuffer == nil {
		return nil, errors.New("invalid EC key, missing x/y values")
	}

	if curveSize(curve) != len(xBuffer.data) {
		return nil, fmt.Errorf("invalid EC public key, wrong length for x")
	}

	if curveSize(curve) != len(yBuffer.data) {
		return nil, fmt.Errorf("invalid EC public key, wrong length for y")
	}

	x := xBuffer.bigInt()
	y := yBuffer.bigInt()

	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("invalid EC key, X/Y are not on declared curve")
	}

	return secp256k1.NewPublicKey(x, y).Serialize(), nil
}

// Get size of curve in bytes
func curveSize(crv elliptic.Curve) int {
	bits := crv.Params().BitSize

	div := bits / bitsPerByte
	mod := bits % bitsPerByte

	if mod == 0 {
		return div
	}

	return div + 1
}

// byteBuffer represents a slice of bytes that can be serialized to url-safe base64.
type byteBuffer struct {
	data []byte
}

func (b *byteBuffer) UnmarshalJSON(data []byte) error {
	var encoded string

	err := json.Unmarshal(data, &encoded)
	if err != nil {
		return err
	}

	if encoded == "" {
		return nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	*b = byteBuffer{
		data: decoded,
	}

	return nil
}

func (b byteBuffer) bigInt() *big.Int {
	return new(big.Int).SetBytes(b.data)
}
