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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/util/cryptoutil"

	"github.com/hyperledger/aries-framework-go/spi/kms"

	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/primitive/bbs12381g2pub"
	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

// TODO: clean up these tests

func Test_CreateKID(t *testing.T) {
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

func TestCreateKID(t *testing.T) {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	kid, err := CreateKID(pubKey, kms.ED25519Type)
	require.NoError(t, err)
	require.NotEmpty(t, kid)

	correctEdKID := createED25519KID(t, pubKey)
	require.Equal(t, correctEdKID, kid)

	_, err = CreateKID(nil, kms.ED25519Type)
	require.EqualError(t, err, "createKID: empty key")

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

	badPubKey := ed25519.PublicKey("badKey")
	_, err = CreateKID(badPubKey, kms.NISTP256ECDHKWType)
	require.EqualError(t, err, "createKID: failed to build jwk: buildJWK: failed to build JWK from ecdh "+
		"key: generateJWKFromECDH: unmarshalECDHKey: failed to unmarshal ECDH key: invalid character 'b' looking for "+
		"beginning of value")

	_, err = CreateKID(badPubKey, kms.ECDSAP256TypeDER)
	require.EqualError(t, err, "createKID: failed to build jwk: buildJWK: failed to build JWK from ecdsa DER "+
		"key: generateJWKFromDERECDSA: failed to parse ecdsa key in DER format: asn1: structure error: tags don't "+
		"match (16 vs {class:1 tag:2 length:97 isCompound:true}) {optional:false explicit:false application:false "+
		"private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} publicKeyInfo "+
		"@2")

	_, err = CreateKID(badPubKey, kms.X25519ECDHKWType)
	require.EqualError(t, err, "createKID: createX25519KID: unmarshalECDHKey: failed to unmarshal ECDH key: "+
		"invalid character 'b' looking for beginning of value")

	_, err = CreateKID(badPubKey, kms.ECDSAP256TypeIEEEP1363)
	require.EqualError(t, err, "createKID: failed to build jwk: buildJWK: failed to build JWK from ecdsa key "+
		"in IEEE1363 format: create JWK: go-jose/go-jose: invalid EC key (nil, or X/Y missing)")

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecKeyBytes := elliptic.Marshal(elliptic.P256(), ecKey.X, ecKey.Y)
	_, err = CreateKID(ecKeyBytes, kms.ECDSAP256TypeIEEEP1363)
	require.NoError(t, err)

	ecKeyBytes, err = x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)

	_, err = CreateKID(ecKeyBytes, kms.ECDSAP256TypeDER)
	require.NoError(t, err)

	x25519 := make([]byte, cryptoutil.Curve25519KeySize)
	_, err = rand.Read(x25519)
	require.NoError(t, err)

	ecdhKey = &cryptoapi.PublicKey{
		Curve: "X25519",
		X:     x25519,
	}

	ecdhKeyMarshalled, err = json.Marshal(ecdhKey)
	require.NoError(t, err)

	kid, err = CreateKID(ecdhKeyMarshalled, kms.X25519ECDHKWType)
	require.NoError(t, err)
	require.NotEmpty(t, kid)
}

func TestCreateKIDFromFixedKey(t *testing.T) {
	// use public key from https://tools.ietf.org/html/rfc8037#appendix-A.2
	refPubKeyB64 := "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	// JWK Thumbprint base64URL from https://tools.ietf.org/html/rfc8037#appendix-A.3
	refKID := "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(refPubKeyB64)
	require.NoError(t, err)

	aPubKey := ed25519.PublicKey(pubKeyBytes)

	kid, err := CreateKID(aPubKey, kms.ED25519Type)
	require.NoError(t, err)
	require.EqualValues(t, refKID, kid)
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

func TestBuildJWKX25519(t *testing.T) {
	x25519 := make([]byte, cryptoutil.Curve25519KeySize)
	_, err := rand.Read(x25519)
	require.NoError(t, err)

	ecdhKey := &cryptoapi.PublicKey{
		Curve: "X25519",
		X:     x25519,
	}

	ecdhKeyMarshalled, err := json.Marshal(ecdhKey)
	require.NoError(t, err)

	t.Run("success buildJWK for X25519", func(t *testing.T) {
		_, err = BuildJWK(ecdhKeyMarshalled, kms.X25519ECDHKWType)
		require.NoError(t, err)
	})

	t.Run("buildJWK for X25519 with invalid marshalled key", func(t *testing.T) {
		_, err = BuildJWK([]byte("invalidKey"), kms.X25519ECDHKWType)
		require.EqualError(t, err, "buildJWK: failed to unmarshal public key from X25519 key: unmarshalECDHKey:"+
			" failed to unmarshal ECDH key: invalid character 'i' looking for beginning of value")
	})

	t.Run("buildJWK for X25519 with invalid key size properly marshalled", func(t *testing.T) {
		ecdhKey = &cryptoapi.PublicKey{
			Curve: "X25519",
			X:     []byte("badKeyvalue"), // invalid key size
		}

		ecdhKeyMarshalled, err = json.Marshal(ecdhKey)
		require.NoError(t, err)

		_, err = BuildJWK(ecdhKeyMarshalled, kms.X25519ECDHKWType)
		require.EqualError(t, err, "buildJWK: failed to build JWK from X25519 key: create JWK: marshalX25519: "+
			"invalid key")
	})
}

func TestBuildJWK_Ed25519(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk, err := BuildJWK(pubKey, kms.ED25519Type)
		require.NoError(t, err)
		require.NotNil(t, jwk)
	})
}

// func TestCreateED25519KID_Failure(t *testing.T) {
//	key := &cryptoapi.PublicKey{
//		Curve: "Ed25519",
//		X:     []byte(strings.Repeat("a", ed25519.PublicKeySize+1)), // public key > Ed25519 key size
//		Y:     []byte{},
//		Type:  ecdhpb.KeyType_OKP.String(),
//	}
//
//	mKey, err := json.Marshal(key)
//	require.NoError(t, err)
//
//	_, err = CreateKID(mKey, kms.ED25519Type)
//	require.EqualError(t, err, "createKID: createED25519KID: invalid Ed25519 key")
// }

func TestCreateBLS12381G2KID(t *testing.T) {
	seed := make([]byte, 32)

	_, err := rand.Read(seed)
	require.NoError(t, err)

	pubKey, _, err := bbs12381g2pub.GenerateKeyPair(sha256.New, seed)
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	kid, err := CreateKID(pubKeyBytes, kms.BLS12381G2Type)
	require.NoError(t, err)
	require.NotEmpty(t, kid)

	_, err = CreateKID(append(pubKeyBytes, []byte("larger key")...), kms.BLS12381G2Type)
	require.EqualError(t, err, "createKID: invalid BBS+ key")
}

func TestCreateSecp256K1KID(t *testing.T) {
	secp256k1Key, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	require.NoError(t, err)

	pubKeyBytes := elliptic.Marshal(secp256k1Key.Curve, secp256k1Key.X, secp256k1Key.Y)

	t.Run("create kid for secp256k1 in DER format", func(t *testing.T) {
		t.Skipf("Secp256k1 keys are not DER compliant")

		kid, e := CreateKID(pubKeyBytes, kms.ECDSASecp256k1TypeDER)
		require.NoError(t, e)
		require.NotEmpty(t, kid)
	})

	t.Run("create kid for secp256k1 in IEEE-1363 format", func(t *testing.T) {
		kid2, e := CreateKID(pubKeyBytes, kms.ECDSASecp256k1TypeIEEEP1363)
		require.NoError(t, e)
		require.NotEmpty(t, kid2)
	})
}

func createED25519KID(t *testing.T, keyBytes []byte) string {
	t.Helper()

	const ed25519ThumbprintTemplate = `{"crv":"Ed25519","kty":"OKP","x":"%s"}`

	lenKey := len(keyBytes)

	require.True(t, lenKey <= ed25519.PublicKeySize, "createED25519KID: invalid Ed25519 key")

	pad := make([]byte, ed25519.PublicKeySize-lenKey)
	ed25519RawKey := append(pad, keyBytes...)

	j := fmt.Sprintf(ed25519ThumbprintTemplate, base64.RawURLEncoding.EncodeToString(ed25519RawKey))

	thumbprint := sha256Sum(j)

	return base64.RawURLEncoding.EncodeToString(thumbprint)
}
