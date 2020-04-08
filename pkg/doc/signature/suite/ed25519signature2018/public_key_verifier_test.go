/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ed25519signature2018

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

func TestPublicKeyVerifier_Verify(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	msg := []byte("test message")

	msgSig := ed25519.Sign(privateKey, msg)

	pubKey := &verifier.PublicKey{
		Type:  kms.ED25519,
		Value: publicKey,
	}
	v := NewPublicKeyVerifier()

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)
}
