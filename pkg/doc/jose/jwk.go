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

	"github.com/btcsuite/btcd/btcec"
	"github.com/square/go-jose/v3"
	"golang.org/x/crypto/ed25519"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

const (
	secp256k1Alg   = "ES256K"
	secp256k1Crv   = "secp256k1"
	secp256k1Kty   = "EC"
	secp256k1Size  = 32
	bitsPerByte    = 8
	x25519Crv      = "X25519"
	ed25519Crv     = "Ed25519"
	okpKty         = "OKP"
	bls12381G2Crv  = "BLS12381G2"
	bls12381G2Size = 96
	blsComprPrivSz = 32
)

// JWK (JSON Web Key) is a JSON data structure that represents a cryptographic key.
type JWK struct {
	jose.JSONWebKey

	Kty string
	Crv string
}

// JWKFromKey creates a JWK from an opaque key struct.
// It's e.g. *ecdsa.PublicKey, *ecdsa.PrivateKey, ed25519.VerificationMethod, *bbs12381g2pub.PrivateKey or
// *bbs12381g2pub.PublicKey.
func JWKFromKey(opaqueKey interface{}) (*JWK, error) {
	key := &JWK{
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
func JWKFromX25519Key(pubKey []byte) (*JWK, error) {
	key := &JWK{
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
func PubKeyBytesToJWK(bytes []byte, keyType kms.KeyType) (*JWK, error) { // nolint:gocyclo
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

// PublicKeyBytes converts a public key to bytes.
// Note: the Public() member function is in go-jose, this means keys not supported by go-jose are not supported using
// j.Public(). Instead use this function to get the public raw bytes.
func (j *JWK) PublicKeyBytes() ([]byte, error) { //nolint:gocyclo
	if j.isBLS12381G2() {
		switch bbsKey := j.Key.(type) {
		case *bbs12381g2pub.PrivateKey:
			return bbsKey.PublicKey().Marshal()
		case *bbs12381g2pub.PublicKey:
			return bbsKey.Marshal()
		}
	}

	if j.isX25519() {
		x25519Key, ok := j.Key.([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid public key in kid '%s'", j.KeyID)
		}

		return x25519Key, nil
	}

	if j.isSecp256k1() {
		var ecPubKey *ecdsa.PublicKey

		ecPubKey, ok := j.Key.(*ecdsa.PublicKey)
		if !ok {
			ecPubKey = &j.Key.(*ecdsa.PrivateKey).PublicKey
		}

		pubKey := &btcec.PublicKey{
			Curve: btcec.S256(),
			X:     ecPubKey.X,
			Y:     ecPubKey.Y,
		}

		return pubKey.SerializeCompressed(), nil
	}

	switch pubKey := j.Public().Key.(type) {
	case ed25519.PublicKey:
		return pubKey, nil
	case *ecdsa.PublicKey:
		return elliptic.Marshal(pubKey, pubKey.X, pubKey.Y), nil
	case *rsa.PublicKey:
		return x509.MarshalPKCS1PublicKey(pubKey), nil
	default:
		return nil, fmt.Errorf("unsupported public key type in kid '%s'", j.KeyID)
	}
}

// UnmarshalJSON reads a key from its JSON representation.
func (j *JWK) UnmarshalJSON(jwkBytes []byte) error {
	var key jsonWebKey

	marshalErr := json.Unmarshal(jwkBytes, &key)
	if marshalErr != nil {
		return fmt.Errorf("unable to read JWK: %w", marshalErr)
	}

	// nolint: gocritic, nestif
	if isSecp256k1(key.Alg, key.Kty, key.Crv) {
		jwk, err := unmarshalSecp256k1(&key)
		if err != nil {
			return fmt.Errorf("unable to read JWK: %w", err)
		}

		*j = *jwk
	} else if isBLS12381G2(key.Kty, key.Crv) {
		jwk, err := unmarshalBLS12381G2(&key)
		if err != nil {
			return fmt.Errorf("unable to read BBS+ JWE: %w", err)
		}

		*j = *jwk
	} else if isX25519(key.Kty, key.Crv) {
		jwk, err := unmarshalX25519(&key)
		if err != nil {
			return fmt.Errorf("unable to read X25519 JWE: %w", err)
		}

		*j = *jwk
	} else {
		var joseJWK jose.JSONWebKey

		err := json.Unmarshal(jwkBytes, &joseJWK)
		if err != nil {
			return fmt.Errorf("unable to read jose JWK, %w", err)
		}

		j.JSONWebKey = joseJWK
	}

	j.Kty = key.Kty
	j.Crv = key.Crv

	return nil
}

// MarshalJSON serializes the given key to its JSON representation.
func (j *JWK) MarshalJSON() ([]byte, error) {
	if j.isSecp256k1() {
		return marshalSecp256k1(j)
	}

	if j.isX25519() {
		return marshalX25519(j)
	}

	if j.isBLS12381G2() {
		return marshalBLS12381G2(j)
	}

	return (&j.JSONWebKey).MarshalJSON()
}

// KeyType returns the kms KeyType of the JWK, or an error if the JWK is of an unrecognized type.
func (j *JWK) KeyType() (kms.KeyType, error) {
	switch key := j.Key.(type) {
	case ed25519.PublicKey, ed25519.PrivateKey:
		return kms.ED25519Type, nil
	case *bbs12381g2pub.PublicKey, *bbs12381g2pub.PrivateKey:
		return kms.BLS12381G2Type, nil
	case *ecdsa.PublicKey:
		return ecdsaPubKeyType(key)
	case *ecdsa.PrivateKey:
		return ecdsaPubKeyType(&(key.PublicKey))
	}

	switch {
	case isX25519(j.Kty, j.Crv):
		return kms.X25519ECDHKWType, nil
	case isEd25519(j.Kty, j.Crv):
		return kms.ED25519Type, nil
	case isSecp256k1(j.Algorithm, j.Kty, j.Crv):
		return kms.ECDSASecp256k1TypeIEEEP1363, nil
	default:
		return "", fmt.Errorf("no keytype recognized for jwk")
	}
}

func ecdsaPubKeyType(pub *ecdsa.PublicKey) (kms.KeyType, error) {
	switch pub.Curve {
	case btcec.S256():
		return kms.ECDSASecp256k1TypeIEEEP1363, nil
	case elliptic.P256():
		return kms.ECDSAP256TypeIEEEP1363, nil
	case elliptic.P384():
		return kms.ECDSAP384TypeIEEEP1363, nil
	case elliptic.P521():
		return kms.ECDSAP521TypeIEEEP1363, nil
	}

	return "", fmt.Errorf("no keytype recognized for ecdsa jwk")
}

func (j *JWK) isX25519() bool {
	switch j.Key.(type) {
	case []byte:
		return isX25519(j.Kty, j.Crv)
	default:
		return false
	}
}

func (j *JWK) isBLS12381G2() bool {
	switch j.Key.(type) {
	case *bbs12381g2pub.PublicKey, *bbs12381g2pub.PrivateKey:
		return true
	default:
		return false
	}
}

func (j *JWK) isSecp256k1() bool {
	return isSecp256k1Key(j.Key) || isSecp256k1(j.Algorithm, j.Kty, j.Crv)
}

func isSecp256k1Key(pubKey interface{}) bool {
	switch key := pubKey.(type) {
	case *ecdsa.PublicKey:
		return key.Curve == btcec.S256()
	case *ecdsa.PrivateKey:
		return key.Curve == btcec.S256()
	default:
		return false
	}
}

func isX25519(kty, crv string) bool {
	return strings.EqualFold(kty, okpKty) && strings.EqualFold(crv, x25519Crv)
}

func isEd25519(kty, crv string) bool {
	return strings.EqualFold(kty, okpKty) && strings.EqualFold(crv, ed25519Crv)
}

func isBLS12381G2(kty, crv string) bool {
	return strings.EqualFold(kty, okpKty) && strings.EqualFold(crv, bls12381G2Crv)
}

func isSecp256k1(alg, kty, crv string) bool {
	return strings.EqualFold(alg, secp256k1Alg) ||
		(strings.EqualFold(kty, secp256k1Kty) && strings.EqualFold(crv, secp256k1Crv))
}

func unmarshalSecp256k1(jwk *jsonWebKey) (*JWK, error) {
	if jwk.X == nil {
		return nil, ErrInvalidKey
	}

	if jwk.Y == nil {
		return nil, ErrInvalidKey
	}

	curve := btcec.S256()

	if curveSize(curve) != len(jwk.X.data) {
		return nil, ErrInvalidKey
	}

	if curveSize(curve) != len(jwk.Y.data) {
		return nil, ErrInvalidKey
	}

	if jwk.D != nil && dSize(curve) != len(jwk.D.data) {
		return nil, ErrInvalidKey
	}

	x := jwk.X.bigInt()
	y := jwk.Y.bigInt()

	if !curve.IsOnCurve(x, y) {
		return nil, ErrInvalidKey
	}

	var key interface{}

	if jwk.D != nil {
		key = &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			},
			D: jwk.D.bigInt(),
		}
	} else {
		key = &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}
	}

	return &JWK{
		JSONWebKey: jose.JSONWebKey{
			Key: key, KeyID: jwk.Kid, Algorithm: jwk.Alg, Use: jwk.Use,
		},
	}, nil
}

func unmarshalX25519(jwk *jsonWebKey) (*JWK, error) {
	if jwk.X == nil {
		return nil, ErrInvalidKey
	}

	if len(jwk.X.data) != cryptoutil.Curve25519KeySize {
		return nil, ErrInvalidKey
	}

	return &JWK{
		JSONWebKey: jose.JSONWebKey{
			Key: jwk.X.data, KeyID: jwk.Kid, Algorithm: jwk.Alg, Use: jwk.Use,
		},
		Crv: jwk.Crv,
		Kty: jwk.Kty,
	}, nil
}

func marshalX25519(jwk *JWK) ([]byte, error) {
	var raw jsonWebKey

	key, ok := jwk.Key.([]byte)
	if !ok {
		return nil, errors.New("marshalX25519: invalid key")
	}

	if len(key) != cryptoutil.Curve25519KeySize {
		return nil, errors.New("marshalX25519: invalid key")
	}

	raw = jsonWebKey{
		Kty: okpKty,
		Crv: x25519Crv,
		X:   newFixedSizeBuffer(key, cryptoutil.Curve25519KeySize),
	}

	raw.Kid = jwk.KeyID
	raw.Alg = jwk.Algorithm
	raw.Use = jwk.Use

	return json.Marshal(raw)
}

func unmarshalBLS12381G2(jwk *jsonWebKey) (*JWK, error) {
	if jwk.X == nil {
		return nil, ErrInvalidKey
	}

	if len(jwk.X.data) != bls12381G2Size {
		return nil, ErrInvalidKey
	}

	if jwk.D != nil && blsComprPrivSz != len(jwk.D.data) {
		return nil, ErrInvalidKey
	}

	var (
		key interface{}
		err error
	)

	if jwk.D != nil {
		key, err = bbs12381g2pub.UnmarshalPrivateKey(jwk.D.data)
		if err != nil {
			return nil, fmt.Errorf("jwk invalid private key unmarshal: %w", err)
		}
	} else {
		key, err = bbs12381g2pub.UnmarshalPublicKey(jwk.X.data)
		if err != nil {
			return nil, fmt.Errorf("jwk invalid public key unmarshal: %w", err)
		}
	}

	return &JWK{
		JSONWebKey: jose.JSONWebKey{
			Key: key, KeyID: jwk.Kid, Algorithm: jwk.Alg, Use: jwk.Use,
		},
		Crv: jwk.Crv,
		Kty: jwk.Kty,
	}, nil
}

func marshalBLS12381G2(jwk *JWK) ([]byte, error) {
	var raw jsonWebKey

	switch key := jwk.Key.(type) {
	case *bbs12381g2pub.PublicKey:
		mKey, err := key.Marshal()
		if err != nil {
			return nil, err
		}

		if len(mKey) != bls12381G2Size {
			return nil, errors.New("marshal BBS public key: invalid key")
		}

		raw = jsonWebKey{
			Kty: okpKty,
			Crv: bls12381G2Crv,
			X:   newFixedSizeBuffer(mKey, bls12381G2Size),
		}
	case *bbs12381g2pub.PrivateKey:
		mPubKey, err := key.PublicKey().Marshal()
		if err != nil {
			return nil, err
		}

		if len(mPubKey) != bls12381G2Size {
			return nil, errors.New("marshal BBS public key: invalid key")
		}

		mPrivKey, err := key.Marshal()
		if err != nil {
			return nil, err
		}

		if len(mPrivKey) != blsComprPrivSz {
			return nil, errors.New("marshal BBS private key: invalid key")
		}

		raw = jsonWebKey{
			Kty: okpKty,
			Crv: bls12381G2Crv,
			X:   newFixedSizeBuffer(mPubKey, bls12381G2Size),
			D:   newFixedSizeBuffer(mPrivKey, blsComprPrivSz),
		}
	default:
		return nil, errors.New("marshalBLS12381G2: invalid key")
	}

	raw.Kid = jwk.KeyID
	raw.Alg = jwk.Algorithm
	raw.Use = jwk.Use

	return json.Marshal(raw)
}

func marshalSecp256k1(jwk *JWK) ([]byte, error) {
	var raw jsonWebKey

	switch ecdsaKey := jwk.Key.(type) {
	case *ecdsa.PublicKey:
		raw = jsonWebKey{
			Kty: secp256k1Kty,
			Crv: secp256k1Crv,
			X:   newFixedSizeBuffer(ecdsaKey.X.Bytes(), secp256k1Size),
			Y:   newFixedSizeBuffer(ecdsaKey.Y.Bytes(), secp256k1Size),
		}

	case *ecdsa.PrivateKey:
		raw = jsonWebKey{
			Kty: secp256k1Kty,
			Crv: secp256k1Crv,
			X:   newFixedSizeBuffer(ecdsaKey.X.Bytes(), secp256k1Size),
			Y:   newFixedSizeBuffer(ecdsaKey.Y.Bytes(), secp256k1Size),
			D:   newFixedSizeBuffer(ecdsaKey.D.Bytes(), dSize(ecdsaKey.Curve)),
		}
	}

	raw.Kid = jwk.KeyID
	raw.Alg = jwk.Algorithm
	raw.Use = jwk.Use

	return json.Marshal(raw)
}

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

// jsonWebKey contains subset of json web key json properties.
type jsonWebKey struct {
	Use string `json:"use,omitempty"`
	Kty string `json:"kty,omitempty"`
	Kid string `json:"kid,omitempty"`
	Crv string `json:"crv,omitempty"`
	Alg string `json:"alg,omitempty"`

	X *byteBuffer `json:"x,omitempty"`
	Y *byteBuffer `json:"y,omitempty"`

	D *byteBuffer `json:"d,omitempty"`
}

// Get size of curve in bytes.
func curveSize(crv elliptic.Curve) int {
	bits := crv.Params().BitSize

	div := bits / bitsPerByte
	mod := bits % bitsPerByte

	if mod == 0 {
		return div
	}

	return div + 1
}

func dSize(curve elliptic.Curve) int {
	order := curve.Params().P
	bitLen := order.BitLen()
	size := bitLen / bitsPerByte

	if bitLen%bitsPerByte != 0 {
		size++
	}

	return size
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

func (b *byteBuffer) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.base64())
}

func (b *byteBuffer) base64() string {
	return base64.RawURLEncoding.EncodeToString(b.data)
}

func (b byteBuffer) bigInt() *big.Int {
	return new(big.Int).SetBytes(b.data)
}

func newFixedSizeBuffer(data []byte, length int) *byteBuffer {
	paddedData := make([]byte, length-len(data))

	return &byteBuffer{
		data: append(paddedData, data...),
	}
}

// ErrInvalidKey is returned when passed JWK is invalid.
var ErrInvalidKey = errors.New("invalid JWK")
