/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"
)

func TestNewECDSAP256Signer(t *testing.T) {
	signer, err := NewECDSAP256Signer()

	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, signer.privateKey)
	require.NotNil(t, signer.PublicKey)
	require.Equal(t, crypto.SHA256, signer.hash)
}

func TestGetECDSAP256Signer(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := GetECDSAP256Signer(privKey)
	require.NotNil(t, signer)
	require.Equal(t, privKey, signer.privateKey)
	require.Equal(t, &privKey.PublicKey, signer.PublicKey)
}

func TestNewECDSASecp256k1Signer(t *testing.T) {
	signer, err := NewECDSASecp256k1Signer()

	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, signer.privateKey)
	require.NotNil(t, signer.PublicKey)
	require.Equal(t, crypto.SHA256, signer.hash)
}

func TestGetECDSASecp256k1Signer(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	require.NoError(t, err)

	signer := GetECDSASecp256k1Signer(privKey)
	require.NotNil(t, signer)
	require.Equal(t, privKey, signer.privateKey)
	require.Equal(t, &privKey.PublicKey, signer.PublicKey)
}

func TestECDSASigner_Sign(t *testing.T) {
	signer, err := NewECDSAP256Signer()
	require.NoError(t, err)

	signature, err := signer.Sign([]byte("test message"))
	require.NoError(t, err)
	require.NotEmpty(t, signature)
}
