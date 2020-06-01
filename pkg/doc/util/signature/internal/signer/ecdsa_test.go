/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"
)

func TestNewECDSAP256Signer(t *testing.T) {
	signer, err := NewECDSAP256Signer()

	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, signer.privateKey)
	require.NotNil(t, signer.PubKey)
	require.Equal(t, crypto.SHA256, signer.hash)
}

func TestGetECDSAP256Signer(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := GetECDSAP256Signer(privKey)
	require.NotNil(t, signer)
	require.Equal(t, privKey, signer.privateKey)
	require.Equal(t, &privKey.PublicKey, signer.PubKey)
}

func TestNewECDSAP384Signer(t *testing.T) {
	signer, err := NewECDSAP384Signer()

	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, signer.privateKey)
	require.NotNil(t, signer.PubKey)
	require.Equal(t, crypto.SHA384, signer.hash)
}

func TestGetECDSAP384Signer(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	signer := GetECDSAP384Signer(privKey)
	require.NotNil(t, signer)
	require.Equal(t, privKey, signer.privateKey)
	require.Equal(t, &privKey.PublicKey, signer.PubKey)
}

func TestNewECDSAP521Signer(t *testing.T) {
	signer, err := NewECDSAP521Signer()

	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, signer.privateKey)
	require.NotNil(t, signer.PubKey)
	require.Equal(t, crypto.SHA512, signer.hash)
}

func TestGetECDSAP521Signer(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	signer := GetECDSAP521Signer(privKey)
	require.NotNil(t, signer)
	require.Equal(t, privKey, signer.privateKey)
	require.Equal(t, &privKey.PublicKey, signer.PubKey)
}

func TestNewECDSASigner(t *testing.T) {
	tests := []struct {
		curve elliptic.Curve
		err   error
	}{
		{elliptic.P256(), nil},
		{elliptic.P384(), nil},
		{elliptic.P521(), nil},
		{btcec.S256(), nil},
		{elliptic.P224(), errors.New("unsupported curve")},
	}

	for _, test := range tests {
		signer, err := NewECDSASigner(test.curve)
		if test.err != nil {
			require.Nil(t, signer)
			require.Error(t, err)
			require.EqualError(t, err, test.err.Error())

			continue
		}

		require.NoError(t, err)
		require.NotNil(t, signer)
	}
}

func TestNewECDSASecp256k1Signer(t *testing.T) {
	signer, err := NewECDSASecp256k1Signer()

	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, signer.privateKey)
	require.NotNil(t, signer.PubKey)
	require.Equal(t, crypto.SHA256, signer.hash)
}

func TestGetECDSASecp256k1Signer(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	require.NoError(t, err)

	signer := GetECDSASecp256k1Signer(privKey)
	require.NotNil(t, signer)
	require.Equal(t, privKey, signer.privateKey)
	require.Equal(t, &privKey.PublicKey, signer.PubKey)
}

func TestECDSASigner_Sign(t *testing.T) {
	signer, err := NewECDSAP256Signer()
	require.NoError(t, err)

	signature, err := signer.Sign([]byte("test message"))
	require.NoError(t, err)
	require.NotEmpty(t, signature)
}
