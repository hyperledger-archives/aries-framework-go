/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	ecdhpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

func TestCreateKID(t *testing.T) {
	t.Run("ED25519 KID", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		kid, err := CreateKID(pubKey, kms.ED25519Type)
		require.NoError(t, err)
		require.NotEmpty(t, kid)

		t.Run("KID for invalid keys", func(t *testing.T) {
			_, err = CreateKID(pubKey, "badType")
			require.EqualError(t, err, "createKID: failed to build jwk: buildJWK: key type is not supported: 'badType'")

			badPubKey := ed25519.PublicKey("badKey")
			_, err = CreateKID(badPubKey, kms.NISTP256ECDHKWType)
			require.EqualError(t, err, "createKID: failed to build jwk: buildJWK: failed to build JWK from ecdh "+
				"key: generateJWKFromECDH: unmarshalECDHKey: failed to unmarshal ECDH key: invalid character 'b' looking for "+
				"beginning of value")
		})
	})

	t.Run("X25519ECDH KID", func(t *testing.T) {
		var kid string

		randomKey := make([]byte, 32)
		_, err := rand.Read(randomKey)
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
	})

	t.Run("ECDSA secp256k1 DER format KID", func(t *testing.T) {
		t.Skip("DER format does not support secp256k1 curve")
		var kid string

		secp256k1Key, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
		require.NoError(t, err)

		pubECKeyBytes := elliptic.Marshal(secp256k1Key.Curve, secp256k1Key.X, secp256k1Key.Y)
		require.NoError(t, err)

		kid, err = CreateKID(pubECKeyBytes, kms.ECDSASecp256k1DER)
		require.NoError(t, err)
		require.NotEmpty(t, kid)
	})

	t.Run("ECDSA secp256k1 IEEE-P1363 format KID", func(t *testing.T) {
		var kid string

		secp256k1Key, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
		require.NoError(t, err)

		pubECKeyBytes := elliptic.Marshal(secp256k1Key.Curve, secp256k1Key.X, secp256k1Key.Y)
		require.NoError(t, err)

		kid, err = CreateKID(pubECKeyBytes, kms.ECDSASecp256k1IEEEP1363)
		require.NoError(t, err)
		require.NotEmpty(t, kid)
	})
}
