/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
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
	_, err = CreateKID(badPubKey, kms.NISTP256ECDHKWType)
	require.EqualError(t, err, "createKID: failed to build jwk: buildJWK: failed to build JWK from ecdh "+
		"key: generateJWKFromECDH: unmarshalECDHKey: failed to unmarshal ECDH key: unexpected end of JSON input")

	_, err = CreateKID(badPubKey, kms.ECDSAP256TypeDER)
	require.EqualError(t, err, "createKID: failed to build jwk: buildJWK: failed to build JWK from ecdsa "+
		"DER key: generateJWKFromDERECDSA: failed to parse ecdsa key in DER format: asn1: syntax error: sequence "+
		"truncated")

	randomKey := make([]byte, 32)
	_, err = rand.Read(randomKey)
	require.NoError(t, err)

	x25519Key := &cryptoapi.PublicKey{
		Curve: "X25519",
		Type:  ecdhpb.KeyType_OKP.String(),
		X:     randomKey,
	}
	mX25519Key, err := json.Marshal(x25519Key)
	require.NoError(t, err)

	kid, err = CreateKID(mX25519Key, kms.X25519ECDHKWType)
	require.NoError(t, err)
	require.NotEmpty(t, kid)
}
