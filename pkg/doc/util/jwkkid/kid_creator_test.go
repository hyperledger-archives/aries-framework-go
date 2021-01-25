/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwkkid

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	commonpb "github.com/google/tink/go/proto/common_go_proto"
	"github.com/stretchr/testify/require"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

func TestCreateKID(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid, err := CreateKID(pubKey, kms.ED25519Type)
	require.NoError(t, err)
	require.NotEmpty(t, kid)

	_, err = CreateKID(nil, kms.ED25519Type)
	require.EqualError(t, err, "createKID: failed to build jwk: buildJWK: failed to build JWK from ed25519 "+
		"key: create JWK: unable to read jose JWK, square/go-jose: unknown curve Ed25519'")

	_, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecdhKey := &cryptoapi.PublicKey{
		Curve: elliptic.P256().Params().Name,
		X:     x.Bytes(),
		Y:     y.Bytes(),
	}

	ecdhKeyMarshalled, err := json.Marshal(ecdhKey)
	require.NoError(t, err)

	kid, err = CreateKID(ecdhKeyMarshalled, kms.NISTP256ECDHKWType)
	require.NoError(t, err)
	require.NotEmpty(t, kid)

	_, err = CreateKID(pubKey, "badType")
	require.EqualError(t, err, "createKID: failed to build jwk: buildJWK: key type is not supported: 'badType'")

	badPubKey := ed25519.PublicKey{}
	_, err = CreateKID(badPubKey, kms.NISTP256ECDHKWType)
	require.EqualError(t, err, "createKID: failed to build jwk: buildJWK: failed to build JWK from ecdh "+
		"key: generateJWKFromECDH: unmarshalECDHKey: failed to unmarshal ECDH key: unexpected end of JSON input")

	_, err = CreateKID(badPubKey, kms.ECDSAP256TypeDER)
	require.EqualError(t, err, "createKID: failed to build jwk: buildJWK: failed to build JWK from ecdsa "+
		"DER key: generateJWKFromDERECDSA: failed to parse ecdsa key in DER format: asn1: syntax error: sequence "+
		"truncated")

	_, err = CreateKID(badPubKey, kms.X25519ECDHKWType)
	require.EqualError(t, err, "createKID: createX25519KID: unmarshalECDHKey: failed to unmarshal ECDH key: "+
		"unexpected end of JSON input")

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecKeyBytes := elliptic.Marshal(elliptic.P256(), ecKey.X, ecKey.Y)
	_, err = CreateKID(ecKeyBytes, kms.ECDSAP256TypeIEEEP1363)
	require.NoError(t, err)
}

func TestGetCurve(t *testing.T) {
	c := getCurveByKMSKeyType(kms.ECDSAP384TypeIEEEP1363)
	require.Equal(t, c, elliptic.P384())

	c = getCurveByKMSKeyType(kms.AES128GCMType) // default P-256 if curve not found
	require.Equal(t, c, elliptic.P256())
}

func TestGenerateJWKFromECDH(t *testing.T) {
	keyBytesWithBadCurve := &cryptoapi.PublicKey{
		Curve: commonpb.EllipticCurveType_UNKNOWN_CURVE.String(),
		X:     []byte{},
		Y:     []byte{},
	}

	badKeyMarshalled, err := json.Marshal(keyBytesWithBadCurve)
	require.NoError(t, err)

	_, err = generateJWKFromECDH(badKeyMarshalled)
	require.EqualError(t, err, "generateJWKFromECDH: failed to get Curve for ECDH key: unsupported curve")
}

func TestCreateX25519KID_Failure(t *testing.T) {
	key := &cryptoapi.PublicKey{
		Curve: "X25519",
		X:     []byte(strings.Repeat("a", cryptoutil.Curve25519KeySize+1)), // public key > X25519 key size
		Y:     []byte{},
		Type:  ecdhpb.KeyType_OKP.String(),
	}

	mKey, err := json.Marshal(key)
	require.NoError(t, err)

	_, err = createX25519KID(mKey)
	require.EqualError(t, err, "createX25519KID: buildX25519JWK: invalid ECDH X25519 key")
}
