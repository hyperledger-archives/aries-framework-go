/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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
	require.EqualError(t, err, "deriveSender1Pu: derive25519KEK with ephemeral key failed: bad input point: "+
		"low order point")

	derivedKEK, err := curve25519.X25519(kekBytes, curve25519.Basepoint)
	require.NoError(t, err)

	// lowOrderPoint from golang.org/x/crypto/curve25519. Causes ED25519 key derivation to fail.
	// https://github.com/golang/crypto/blob/f4817d981/curve25519/vectors_test.go#L10
	lowOrderPoint := []byte{
		0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	}

	_, err = okpKW.deriveSender1Pu("", nil, nil, derivedKEK, kekBytes, lowOrderPoint, 0)
	require.EqualError(t, err, "deriveSender1Pu: derive25519KEK with ephemeral key failed: bad input point: "+
		"low order point")
	// can't reproduce key derivation error with sender key because recipient public key as lowOrderPoint fails for
	// ephemeral key derivation. ie sender key derivation failure only fails if ephemeral key derivation fails.

	_, err = okpKW.deriveRecipient1Pu("", nil, nil, "badEphemeralPrivKeyType", nil, nil, 0)
	require.EqualError(t, err, "deriveRecipient1Pu: ephemeral key not OKP type")

	_, err = okpKW.deriveRecipient1Pu("", nil, nil, []byte{}, "badSenderPrivKeyType", nil, 0)
	require.EqualError(t, err, "deriveRecipient1Pu: sender key not OKP type")

	_, err = okpKW.deriveRecipient1Pu("", nil, nil, []byte{}, []byte{}, "badSenderPrivKeyType", 0)
	require.EqualError(t, err, "deriveRecipient1Pu: recipient key not OKP type")

	_, err = okpKW.deriveRecipient1Pu("", nil, nil, []byte{}, []byte{}, []byte{}, 0)
	require.EqualError(t, err, "deriveRecipient1Pu: derive25519KEK with ephemeral key failed: bad input point:"+
		" low order point")
}
