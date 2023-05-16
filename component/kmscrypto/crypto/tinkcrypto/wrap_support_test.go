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
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/util/cryptoutil"
)

func Test_ecKWSupportFailures(t *testing.T) {
	ecKW := &ecKWSupport{}

	_, err := ecKW.wrap("badCipherBlockType", []byte(""))
	require.EqualError(t, err, "wrap support: EC wrap with invalid cipher block type")

	_, err = ecKW.unwrap("badCipherBlockType", []byte(""))
	require.EqualError(t, err, "unwrap support: EC wrap with invalid cipher block type")

	_, err = ecKW.deriveSender1Pu("", nil, nil, nil, "badEphemeralPrivKeyType", nil, nil, 0)
	require.EqualError(t, err, "deriveSender1Pu: ephemeral key not ECDSA type")

	_, err = ecKW.deriveSender1Pu("", nil, nil, nil, &ecdsa.PrivateKey{}, "badSenderPrivKeyType", nil, 0)
	require.EqualError(t, err, "deriveSender1Pu: sender key not ECDSA type")

	_, err = ecKW.deriveSender1Pu("", nil, nil, nil, &ecdsa.PrivateKey{}, &ecdsa.PrivateKey{}, "badSenderPrivKeyType", 0)
	require.EqualError(t, err, "deriveSender1Pu: recipient key not ECDSA type")

	_, err = ecKW.deriveSender1Pu("", nil, nil, nil, &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()},
	}, &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P521()},
	}, &ecdsa.PublicKey{Curve: elliptic.P521()}, 0)
	require.EqualError(t, err, "deriveSender1Pu: recipient, sender and ephemeral key are not on the same curve")

	_, err = ecKW.deriveSender1Pu("", nil, nil, nil, &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P521()},
	}, &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()},
	}, &ecdsa.PublicKey{Curve: elliptic.P521()}, 0)
	require.EqualError(t, err, "deriveSender1Pu: recipient, sender and ephemeral key are not on the same curve")

	_, err = ecKW.deriveRecipient1Pu("", nil, nil, nil, "badEphemeralPrivKeyType", nil, nil, 0)
	require.EqualError(t, err, "deriveRecipient1Pu: ephemeral key not ECDSA type")

	_, err = ecKW.deriveRecipient1Pu("", nil, nil, nil, &ecdsa.PublicKey{}, "badSenderPrivKeyType", nil, 0)
	require.EqualError(t, err, "deriveRecipient1Pu: sender key not ECDSA type")

	_, err = ecKW.deriveRecipient1Pu("", nil, nil, nil, &ecdsa.PublicKey{}, &ecdsa.PublicKey{}, "badSenderPrivKeyType", 0)
	require.EqualError(t, err, "deriveRecipient1Pu: recipient key not ECDSA type")

	_, err = ecKW.deriveRecipient1Pu("", nil, nil, nil, &ecdsa.PublicKey{Curve: elliptic.P521()},
		&ecdsa.PublicKey{Curve: elliptic.P521()}, &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}}, 0)
	require.EqualError(t, err, "deriveRecipient1Pu: recipient, sender and ephemeral key are not on the same curve")

	_, err = ecKW.deriveRecipient1Pu("", nil, nil, nil, &ecdsa.PublicKey{Curve: elliptic.P521()},
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

	_, err = okpKW.deriveSender1Pu("", nil, nil, nil, "badEphemeralPrivKeyType", nil, nil, 0)
	require.EqualError(t, err, "deriveSender1Pu: ephemeral key not OKP type")

	_, err = okpKW.deriveSender1Pu("", nil, nil, nil, []byte{}, "badSenderPrivKeyType", nil, 0)
	require.EqualError(t, err, "deriveSender1Pu: sender key not OKP type")

	_, err = okpKW.deriveSender1Pu("", nil, nil, nil, []byte{}, []byte{}, "badSenderPrivKeyType", 0)
	require.EqualError(t, err, "deriveSender1Pu: recipient key not OKP type")

	_, err = okpKW.deriveSender1Pu("", nil, nil, nil, []byte{}, []byte{}, []byte{}, 0)
	require.EqualError(t, err, "deriveSender1Pu: deriveECDHX25519: bad input point: low order point")

	derivedKEK, err := curve25519.X25519(kekBytes, curve25519.Basepoint)
	require.NoError(t, err)

	// lowOrderPoint from golang.org/x/crypto/curve25519. Causes ED25519 key derivation to fail.
	// https://github.com/golang/crypto/blob/f4817d981/curve25519/vectors_test.go#L10
	lowOrderPoint := []byte{
		0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	}

	_, err = okpKW.deriveSender1Pu("", nil, nil, nil, derivedKEK, kekBytes, lowOrderPoint, 0)
	require.EqualError(t, err, "deriveSender1Pu: deriveECDHX25519: bad input point: low order point")
	// can't reproduce key derivation error with sender key because recipient public key as lowOrderPoint fails for
	// ephemeral key derivation. ie sender key derivation failure only fails if ephemeral key derivation fails.

	_, err = okpKW.deriveRecipient1Pu("", nil, nil, nil, "badEphemeralPrivKeyType", nil, nil, 0)
	require.EqualError(t, err, "deriveRecipient1Pu: ephemeral key not OKP type")

	_, err = okpKW.deriveRecipient1Pu("", nil, nil, nil, []byte{}, "badSenderPrivKeyType", nil, 0)
	require.EqualError(t, err, "deriveRecipient1Pu: sender key not OKP type")

	_, err = okpKW.deriveRecipient1Pu("", nil, nil, nil, []byte{}, []byte{}, "badSenderPrivKeyType", 0)
	require.EqualError(t, err, "deriveRecipient1Pu: recipient key not OKP type")

	_, err = okpKW.deriveRecipient1Pu("", nil, nil, nil, []byte{}, []byte{}, []byte{}, 0)
	require.EqualError(t, err, "deriveRecipient1Pu: deriveECDHX25519: bad input point: low order point")
}

type mockKey struct {
	Kty string `json:"kty,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`
}

type mockProtectedHeader struct {
	Alg string  `json:"alg,omitempty"`
	Enc string  `json:"enc,omitempty"`
	Apu string  `json:"apu,omitempty"`
	Apv string  `json:"apv,omitempty"`
	Epk mockKey `json:"epk,omitempty"`
}

type ref1PU struct {
	ZeHex           string `json:"zeHex,omitempty"`
	ZsHex           string `json:"zsHex,omitempty"`
	ZHex            string `json:"zHex,omitempty"`
	Sender1PUKDFHex string `json:"sender1puKdfHex,omitempty"`
	Sender1PUKWB64  string `json:"sender1puKwB64,omitempty"`
}

func refJWKtoOKPKey(t *testing.T, jwkM string) (*[chacha20poly1305.KeySize]byte, *[chacha20poly1305.KeySize]byte) {
	t.Helper()

	jwk := &mockKey{}
	err := json.Unmarshal([]byte(jwkM), jwk)
	require.NoError(t, err)

	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	require.NoError(t, err)

	d, err := base64.RawURLEncoding.DecodeString(jwk.D)
	require.NoError(t, err)

	x32 := new([chacha20poly1305.KeySize]byte)
	copy(x32[:], x)

	d32 := new([chacha20poly1305.KeySize]byte)
	copy(d32[:], d)

	return x32, d32
}

// nolint:gochecknoglobals // embedded test data
var (
	// test vector retrieved from:
	//nolint:lll
	// (github: https://github.com/NeilMadden/jose-ecdh-1pu/blob/master/draft-madden-jose-ecdh-1pu-04/draft-madden-jose-ecdh-1pu-04.txt#L740)
	// (ietf draft: https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#appendix-B)
	//go:embed testdata/alice_key_ref.json
	aliceKeyRef string
	//go:embed testdata/bob_key_ref.json
	bobKeyRef string
	//go:embed testdata/charlie_key_ref.json
	charlieKeyRef string
	//go:embed testdata/alice_epk_ref.json
	aliceEPKRef string
	//go:embed testdata/protected_headers_ref.json
	protectedHeadersRef string
	//go:embed testdata/ecdh_1pu_bob.json
	ecdh1puBobRef string
	//go:embed testdata/ecdh_1pu_charlie.json
	ecdh1puCharlieRef string
)

// TestDeriveReferenceKey uses the test vector in the 1PU draft found at:
// (github: https://github.com/NeilMadden/jose-ecdh-1pu/blob/master/draft-madden-jose-ecdh-1pu-03.txt#L459)
// (ietf draft: https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03#appendix-A)
// to validate the ECDH-1PU key derivation.
func TestDeriveReferenceKey(t *testing.T) {
	tag, err := base64.RawURLEncoding.DecodeString("HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ")
	require.NoError(t, err)

	cek, err := hex.DecodeString("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8" +
		"d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0")
	require.NoError(t, err)

	ref1PUBobData := &ref1PU{}
	err = json.Unmarshal([]byte(ecdh1puBobRef), ref1PUBobData)
	require.NoError(t, err)

	ref1PUCharlieData := &ref1PU{}
	err = json.Unmarshal([]byte(ecdh1puCharlieRef), ref1PUCharlieData)
	require.NoError(t, err)

	_, alicePrivKeyRefOKP := refJWKtoOKPKey(t, aliceKeyRef)
	bobPubKeyRefOKP, _ := refJWKtoOKPKey(t, bobKeyRef)
	charliePubKeyRefOKP, _ := refJWKtoOKPKey(t, charlieKeyRef)
	_, alicePrivKeyEPKRefOKP := refJWKtoOKPKey(t, aliceEPKRef)

	protectedHeaderRefJWK := &mockProtectedHeader{}
	err = json.Unmarshal([]byte(protectedHeadersRef), protectedHeaderRefJWK)
	require.NoError(t, err)

	apuRef, err := base64.RawURLEncoding.DecodeString(protectedHeaderRefJWK.Apu) // "Alice"
	require.NoError(t, err)

	apvRef, err := base64.RawURLEncoding.DecodeString(protectedHeaderRefJWK.Apv) // "Bob and Charlie"
	require.NoError(t, err)

	zeBobRef, err := hex.DecodeString(ref1PUBobData.ZeHex)
	require.NoError(t, err)

	zeCharlieRef, err := hex.DecodeString(ref1PUCharlieData.ZeHex)
	require.NoError(t, err)

	t.Run("test derive Ze for Bob", func(t *testing.T) {
		ze, e := cryptoutil.DeriveECDHX25519(alicePrivKeyEPKRefOKP, bobPubKeyRefOKP)
		require.NoError(t, e)
		require.EqualValues(t, zeBobRef, ze)

		zeHEX := hex.EncodeToString(ze)
		require.EqualValues(t, ref1PUBobData.ZeHex, zeHEX)
	})

	t.Run("test derive Ze for Charlie", func(t *testing.T) {
		ze, e := cryptoutil.DeriveECDHX25519(alicePrivKeyEPKRefOKP, charliePubKeyRefOKP)
		require.NoError(t, e)

		zeHEX := hex.EncodeToString(ze)
		require.EqualValues(t, ref1PUCharlieData.ZeHex, zeHEX)
		require.EqualValues(t, zeCharlieRef, ze)
	})

	zsBobRef, err := hex.DecodeString(ref1PUBobData.ZsHex)
	require.NoError(t, err)

	t.Run("test derive Zs for Bob", func(t *testing.T) {
		zs, e := cryptoutil.DeriveECDHX25519(alicePrivKeyRefOKP, bobPubKeyRefOKP)
		require.NoError(t, e)

		zsHEX := hex.EncodeToString(zs)
		require.EqualValues(t, ref1PUBobData.ZsHex, zsHEX)
		require.EqualValues(t, zsBobRef, zs)
	})

	zsCharlieRef, err := hex.DecodeString(ref1PUCharlieData.ZsHex)
	require.NoError(t, err)

	t.Run("test derive Zs for Charlie", func(t *testing.T) {
		zs, e := cryptoutil.DeriveECDHX25519(alicePrivKeyRefOKP, charliePubKeyRefOKP)
		require.NoError(t, e)

		zsHEX := hex.EncodeToString(zs)
		require.EqualValues(t, ref1PUCharlieData.ZsHex, zsHEX)
		require.EqualValues(t, zsCharlieRef, zs)
	})

	zBob, err := hex.DecodeString(ref1PUBobData.ZHex)
	require.NoError(t, err)
	require.EqualValues(t, append(zeBobRef, zsBobRef...), zBob)

	zCharlie, err := hex.DecodeString(ref1PUCharlieData.ZHex)
	require.NoError(t, err)
	require.EqualValues(t, append(zeCharlieRef, zsCharlieRef...), zCharlie)

	onePUKDFBobFromHex, err := hex.DecodeString(ref1PUBobData.Sender1PUKDFHex)
	require.NoError(t, err)

	onePUKDFCharlieFromHex, err := hex.DecodeString(ref1PUCharlieData.Sender1PUKDFHex)
	require.NoError(t, err)

	okpWrapper := okpKWSupport{}

	t.Run("test KDF for Bob", func(t *testing.T) {
		sender1PUWithBobKDF, e := okpWrapper.deriveSender1Pu(protectedHeaderRefJWK.Alg, apuRef, apvRef, tag,
			alicePrivKeyEPKRefOKP[:], alicePrivKeyRefOKP[:], bobPubKeyRefOKP[:], 32)
		require.NoError(t, e)
		require.EqualValues(t, onePUKDFBobFromHex, sender1PUWithBobKDF)
	})

	t.Run("test KDF for Charlie", func(t *testing.T) {
		sender1PUWithCharlieKDF, e := okpWrapper.deriveSender1Pu(protectedHeaderRefJWK.Alg, apuRef, apvRef, tag,
			alicePrivKeyEPKRefOKP[:], alicePrivKeyRefOKP[:], charliePubKeyRefOKP[:], 32)
		require.NoError(t, e)
		require.EqualValues(t, onePUKDFCharlieFromHex, sender1PUWithCharlieKDF)
	})

	// Appendix B example uses "A128KW" key wrapping.
	ecKW := &ecKWSupport{}

	t.Run("test key wrap for Bob", func(t *testing.T) {
		bobAESBlock, err := ecKW.createPrimitive(onePUKDFBobFromHex)
		require.NoError(t, err)

		onePUKWBobFromB64, err := base64.RawURLEncoding.DecodeString(ref1PUBobData.Sender1PUKWB64)
		require.NoError(t, err)

		bobEncryptedKey, err := ecKW.wrap(bobAESBlock, cek)
		require.NoError(t, err)
		require.EqualValues(t, onePUKWBobFromB64, bobEncryptedKey)

		bobDecryptedCEK, err := ecKW.unwrap(bobAESBlock, onePUKWBobFromB64)
		require.NoError(t, err)
		require.EqualValues(t, cek, bobDecryptedCEK)
	})

	t.Run("test key wrap for Charlie", func(t *testing.T) {
		charlieAESBlock, err := ecKW.createPrimitive(onePUKDFCharlieFromHex)
		require.NoError(t, err)

		onePUKWCharlieFromB64, err := base64.RawURLEncoding.DecodeString(ref1PUCharlieData.Sender1PUKWB64)
		require.NoError(t, err)

		charlieEncryptedKey, err := ecKW.wrap(charlieAESBlock, cek)
		require.NoError(t, err)
		require.EqualValues(t, onePUKWCharlieFromB64, charlieEncryptedKey)

		charlieDecryptedCEK, err := ecKW.unwrap(charlieAESBlock, onePUKWCharlieFromB64)
		require.NoError(t, err)
		require.EqualValues(t, cek, charlieDecryptedCEK)
	})
}
