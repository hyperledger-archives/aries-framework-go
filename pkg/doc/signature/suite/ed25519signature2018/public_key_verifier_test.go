/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ed25519signature2018

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

func TestPublicKeyVerifier_Verify(t *testing.T) {
	signer, err := signature.NewEd25519Signer()
	require.NoError(t, err)

	msg := []byte("test message")

	msgSig, err := signer.Sign(msg)
	require.NoError(t, err)

	pubKey := &verifier.PublicKey{
		Type:  kms.ED25519,
		Value: signer.PublicKey,
	}
	v := NewPublicKeyVerifier()

	err = v.Verify(pubKey, msg, msgSig)
	require.NoError(t, err)
}
