/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

func TestCreateKID(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid, err := CreateKID(pubKey, kms.ED25519Type)
	require.NoError(t, err)
	require.NotEmpty(t, kid)

	_, err = CreateKID(pubKey, "badType")
	require.EqualError(t, err, "createKID: failed to build jwk: buildJWK: key type is not supported: 'badType'")

	badPubKey := ed25519.PublicKey{}
	_, err = CreateKID(badPubKey, kms.ECDH1PU256AES256GCMType)
	require.EqualError(t, err, "createKID: failed to build jwk: buildJWK: failed to build JWK from ecdh "+
		"key: generateJWKFromECDH: failed to unmarshal ECDH key: unexpected end of JSON input")

	_, err = CreateKID(badPubKey, kms.ECDSAP256TypeDER)
	require.EqualError(t, err, "createKID: failed to build jwk: buildJWK: failed to build JWK from ecdsa "+
		"DER key: generateJWKFromDERECDSA: failed to parse ecdsa key in DER format: asn1: syntax error: sequence "+
		"truncated")
}

func TestGetCurve(t *testing.T) {
	c := getCurve(kms.ECDSAP384TypeIEEEP1363)
	require.Equal(t, c, elliptic.P384())

	c = getCurve(kms.AES128GCMType) // default P-256 if curve not found
	require.Equal(t, c, elliptic.P256())
}
