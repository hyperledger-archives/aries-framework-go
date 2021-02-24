/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"crypto/rand"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"
)

func TestBBSKeyTemplateSuccess(t *testing.T) {
	kt := BLS12381G2KeyTemplate()

	kh, err := keyset.NewHandle(kt)
	require.NoError(t, err)

	pubKH, err := kh.Public()
	require.NoError(t, err)

	// now test the BBS primitives with these keyset handles
	signer, err := NewSigner(kh)
	require.NoError(t, err)

	messages := [][]byte{[]byte("msg abc"), []byte("msg def"), []byte("msg ghi")}

	sig, err := signer.Sign(messages)
	require.NoError(t, err)

	verifier, err := NewVerifier(pubKH)
	require.NoError(t, err)

	err = verifier.Verify(messages, sig)
	require.NoError(t, err)

	revealedIndexes := []int{1, 2}
	nonce := make([]byte, 10)

	_, err = rand.Read(nonce)
	require.NoError(t, err)

	proof, err := verifier.DeriveProof(messages, sig, nonce, revealedIndexes)
	require.NoError(t, err)

	revealedMsgs := [][]byte{messages[1], messages[2]}

	err = verifier.VerifyProof(revealedMsgs, proof, nonce)
	require.NoError(t, err)
}
