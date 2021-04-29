/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

func Test_ecKWSupportFailures(t *testing.T) {
	ecKW := &ecKWSupport{}

	_, err := ecKW.wrap("badCipherBlockType", []byte(""))
	require.EqualError(t, err, "wrap support: EC wrap with invalid cipher block type")

	_, err = ecKW.unwrap("badCipherBlockType", []byte(""))
	require.EqualError(t, err, "unwrap support: EC wrap with invalid cipher block type")

	_, err = ecKW.deriveSender1Pu("", nil, nil, "badEphemeralPrivKeyType", nil, nil, 0)
	require.EqualError(t, err, "deriveSender1Pu: ephemeral key not ECDSA type")

	_, err = ecKW.deriveSender1Pu("", nil, nil, &ecdsa.PrivateKey{}, "badSenderPrivKeyType", nil, 0)
	require.EqualError(t, err, "deriveSender1Pu: sender key not ECDSA type")

	_, err = ecKW.deriveSender1Pu("", nil, nil, &ecdsa.PrivateKey{}, &ecdsa.PrivateKey{}, "badSenderPrivKeyType", 0)
	require.EqualError(t, err, "deriveSender1Pu: recipient key not ECDSA type")

	_, err = ecKW.deriveSender1Pu("", nil, nil, &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()},
	}, &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P521()},
	}, &ecdsa.PublicKey{Curve: elliptic.P521()}, 0)
	require.EqualError(t, err, "deriveSender1Pu: recipient, sender and ephemeral key are not on the same curve")

	_, err = ecKW.deriveSender1Pu("", nil, nil, &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P521()},
	}, &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()},
	}, &ecdsa.PublicKey{Curve: elliptic.P521()}, 0)
	require.EqualError(t, err, "deriveSender1Pu: recipient, sender and ephemeral key are not on the same curve")

	_, err = ecKW.deriveRecipient1Pu("", nil, nil, "badEphemeralPrivKeyType", nil, nil, 0)
	require.EqualError(t, err, "deriveRecipient1Pu: ephemeral key not ECDSA type")

	_, err = ecKW.deriveRecipient1Pu("", nil, nil, &ecdsa.PublicKey{}, "badSenderPrivKeyType", nil, 0)
	require.EqualError(t, err, "deriveRecipient1Pu: sender key not ECDSA type")

	_, err = ecKW.deriveRecipient1Pu("", nil, nil, &ecdsa.PublicKey{}, &ecdsa.PublicKey{}, "badSenderPrivKeyType", 0)
	require.EqualError(t, err, "deriveRecipient1Pu: recipient key not ECDSA type")

	_, err = ecKW.deriveRecipient1Pu("", nil, nil, &ecdsa.PublicKey{Curve: elliptic.P521()},
		&ecdsa.PublicKey{Curve: elliptic.P521()}, &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}}, 0)
	require.EqualError(t, err, "deriveRecipient1Pu: recipient, sender and ephemeral key are not on the same curve")

	_, err = ecKW.deriveRecipient1Pu("", nil, nil, &ecdsa.PublicKey{Curve: elliptic.P521()},
		&ecdsa.PublicKey{Curve: elliptic.P256()}, &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P521()}}, 0)
	require.EqualError(t, err, "deriveRecipient1Pu: recipient, sender and ephemeral key are not on the same curve")
}

func Test_okpKWSupportFailures(t *testing.T) {
	okpKW := &okpKWSupport{}

	_, err := okpKW.getCurve("")
	require.EqualError(t, err, "getCurve: not implemented for OKP KW support")

	_, err = okpKW.createPrimitive([]byte("kekWithBadSize"))
	require.EqualError(t, err, "createPrimitive: failed to create OKP primitive: chacha20poly1305: bad key length")

	_, err = okpKW.wrap("badCipherBlockType", []byte(""))
	require.EqualError(t, err, "wrap support: OKP wrap with invalid primitive type")

	_, err = okpKW.unwrap("badCipherBlockType", []byte(""))
	require.EqualError(t, err, "unwrap support: OKP unwrap with invalid primitive type")

	kek, err := okpKW.generateKey(nil)
	require.NoError(t, err)

	kekBytes, ok := kek.([]byte)
	require.True(t, ok)

	XC20PPrimitive, err := okpKW.createPrimitive(kekBytes)
	require.NoError(t, err)

	_, err = okpKW.unwrap(XC20PPrimitive, []byte(""))
	require.EqualError(t, err, "unwrap support: OKP unwrap invalid key")

	_, err = okpKW.unwrap(XC20PPrimitive, []byte("badEncryptedKeyLargerThankNonceSize"))
	require.EqualError(t, err, "unwrap support: OKP failed to unwrap key: chacha20poly1305: message authentication failed")

	_, err = okpKW.deriveSender1Pu("", nil, nil, "badEphemeralPrivKeyType", nil, nil, 0)
	require.EqualError(t, err, "deriveSender1Pu: ephemeral key not OKP type")

	_, err = okpKW.deriveSender1Pu("", nil, nil, []byte{}, "badSenderPrivKeyType", nil, 0)
	require.EqualError(t, err, "deriveSender1Pu: sender key not OKP type")

	_, err = okpKW.deriveSender1Pu("", nil, nil, []byte{}, []byte{}, "badSenderPrivKeyType", 0)
	require.EqualError(t, err, "deriveSender1Pu: recipient key not OKP type")

	_, err = okpKW.deriveSender1Pu("", nil, nil, []byte{}, []byte{}, []byte{}, 0)
	require.EqualError(t, err, "deriveSender1Pu: deriveECDHX25519: bad input point: low order point")

	derivedKEK, err := curve25519.X25519(kekBytes, curve25519.Basepoint)
	require.NoError(t, err)

	// lowOrderPoint from golang.org/x/crypto/curve25519. Causes ED25519 key derivation to fail.
	// https://github.com/golang/crypto/blob/f4817d981/curve25519/vectors_test.go#L10
	lowOrderPoint := []byte{
		0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	}

	_, err = okpKW.deriveSender1Pu("", nil, nil, derivedKEK, kekBytes, lowOrderPoint, 0)
	require.EqualError(t, err, "deriveSender1Pu: deriveECDHX25519: bad input point: low order point")
	// can't reproduce key derivation error with sender key because recipient public key as lowOrderPoint fails for
	// ephemeral key derivation. ie sender key derivation failure only fails if ephemeral key derivation fails.

	_, err = okpKW.deriveRecipient1Pu("", nil, nil, "badEphemeralPrivKeyType", nil, nil, 0)
	require.EqualError(t, err, "deriveRecipient1Pu: ephemeral key not OKP type")

	_, err = okpKW.deriveRecipient1Pu("", nil, nil, []byte{}, "badSenderPrivKeyType", nil, 0)
	require.EqualError(t, err, "deriveRecipient1Pu: sender key not OKP type")

	_, err = okpKW.deriveRecipient1Pu("", nil, nil, []byte{}, []byte{}, "badSenderPrivKeyType", 0)
	require.EqualError(t, err, "deriveRecipient1Pu: recipient key not OKP type")

	_, err = okpKW.deriveRecipient1Pu("", nil, nil, []byte{}, []byte{}, []byte{}, 0)
	require.EqualError(t, err, "deriveRecipient1Pu: deriveECDHX25519: bad input point: low order point")
}

type mockKey struct {
	Kty string `json:"kty,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`
}

type mockRecipient struct {
	Alg string  `json:"alg,omitempty"`
	Enc string  `json:"enc,omitempty"`
	Apu string  `json:"apu,omitempty"`
	Apv string  `json:"apv,omitempty"`
	Epk mockKey `json:"epk,omitempty"`
}

type ref1PU struct {
	ZeHex        string `json:"zeHex,omitempty"`
	ZsHex        string `json:"zsHex,omitempty"`
	ZHex         string `json:"zHex,omitempty"`
	Sender1PUHex string `json:"sender1puHex,omitempty"`
	Sender1PUB64 string `json:"sender1puB64,omitempty"`
}

func refJWKtoECKey(t *testing.T, jwkMarshalled string) *ecdsa.PrivateKey {
	t.Helper()

	jwk := &mockKey{}
	err := json.Unmarshal([]byte(jwkMarshalled), jwk)
	require.NoError(t, err)

	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	require.NoError(t, err)

	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	require.NoError(t, err)

	d, err := base64.RawURLEncoding.DecodeString(jwk.D)
	require.NoError(t, err)

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		},
		D: new(big.Int).SetBytes(d),
	}
}

// nolint:gochecknoglobals // embedded test data
var (
	// test vector retrieved from:
	// (github: https://github.com/NeilMadden/jose-ecdh-1pu/blob/master/draft-madden-jose-ecdh-1pu-03.txt#L459)
	// (ietf draft: https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03#appendix-A)
	//go:embed testdata/alice_key_ref.json
	aliceKeyRef string
	//go:embed testdata/bob_key_ref.json
	bobKeyRef string
	//go:embed testdata/alice_epk_ref.json
	aliceEPKRef string
	//go:embed testdata/recipient_ref.json
	recipientRef string
	//go:embed testdata/ecdh_1pu.json
	ecdh1puRef string
)

// TestDeriveReferenceKey uses the test vector in the 1PU draft found at:
// (github: https://github.com/NeilMadden/jose-ecdh-1pu/blob/master/draft-madden-jose-ecdh-1pu-03.txt#L459)
// (ietf draft: https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03#appendix-A)
// to validate the ECDH-1PU key derivation.
func TestDeriveReferenceKey(t *testing.T) {
	ref1PUData := &ref1PU{}
	err := json.Unmarshal([]byte(ecdh1puRef), ref1PUData)
	require.NoError(t, err)

	alicePrivKeyRefEC := refJWKtoECKey(t, aliceKeyRef)
	bobPrivKeyEPKRefEC := refJWKtoECKey(t, bobKeyRef)
	alicePrivKeyEPKRefEC := refJWKtoECKey(t, aliceEPKRef)

	recipientRefJWK := &mockRecipient{}
	err = json.Unmarshal([]byte(recipientRef), recipientRefJWK)
	require.NoError(t, err)

	apuRef, err := base64.RawURLEncoding.DecodeString(recipientRefJWK.Apu) // "Alice"
	require.NoError(t, err)

	apvRef, err := base64.RawURLEncoding.DecodeString(recipientRefJWK.Apv) // "Bob"
	require.NoError(t, err)

	zeRef, err := hex.DecodeString(ref1PUData.ZeHex)
	require.NoError(t, err)

	t.Run("test derive Ze", func(t *testing.T) {
		ze := deriveECDH(alicePrivKeyEPKRefEC, &bobPrivKeyEPKRefEC.PublicKey, 32)
		zeHEX := hex.EncodeToString(ze)
		require.EqualValues(t, ref1PUData.ZeHex, zeHEX)
		require.EqualValues(t, zeRef, ze)
	})

	zsRef, err := hex.DecodeString(ref1PUData.ZsHex)
	require.NoError(t, err)

	t.Run("test derive Zs", func(t *testing.T) {
		zs := deriveECDH(alicePrivKeyRefEC, &bobPrivKeyEPKRefEC.PublicKey, 32)
		zsHEX := hex.EncodeToString(zs)
		require.EqualValues(t, ref1PUData.ZsHex, zsHEX)
		require.EqualValues(t, zsRef, zs)
	})

	z, err := hex.DecodeString(ref1PUData.ZHex)
	require.NoError(t, err)
	require.EqualValues(t, append(zeRef, zsRef...), z)

	ecWrapper := ecKWSupport{}

	sender1PU, err := ecWrapper.deriveSender1Pu(recipientRefJWK.Enc, apuRef, apvRef, alicePrivKeyEPKRefEC,
		alicePrivKeyRefEC, &bobPrivKeyEPKRefEC.PublicKey, 32)
	require.NoError(t, err)

	onePUFromHex, err := hex.DecodeString(ref1PUData.Sender1PUHex)
	require.NoError(t, err)

	onePUFromB64, err := base64.RawURLEncoding.DecodeString(ref1PUData.Sender1PUB64)
	require.NoError(t, err)
	require.EqualValues(t, onePUFromHex, onePUFromB64)
	require.EqualValues(t, onePUFromB64, sender1PU)
}
