/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package secp256k1_test

import (
	"fmt"
	"testing"

	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/secp256k1"
)

func TestKeyTemplates(t *testing.T) {
	derKeyTemplate, err := secp256k1.DERKeyTemplate()
	require.NoError(t, err)

	ieeeKeyTempalte, err := secp256k1.IEEEP1363KeyTemplate()
	require.NoError(t, err)

	testCases := []struct {
		name     string
		template *tinkpb.KeyTemplate
	}{
		{
			name:     "SECP256K1",
			template: derKeyTemplate,
		},
		{
			name:     "SECP256K1",
			template: ieeeKeyTempalte,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var kh *keyset.Handle

			kh, err = keyset.NewHandle(tc.template)
			require.NoError(t, err)

			err = testSignVerify(kh)
			require.NoError(t, err)
		})
	}
}

func testSignVerify(privateHandle *keyset.Handle) error {
	signer, err := secp256k1.NewSigner(privateHandle)
	if err != nil {
		return fmt.Errorf("signature.NewSigner(privateHandle) failed: %w", err)
	}

	publicHandle, err := privateHandle.Public()
	if err != nil {
		return fmt.Errorf("privateHandle.Public() failed: %w", err)
	}

	verifier, err := secp256k1.NewVerifier(publicHandle)
	if err != nil {
		return fmt.Errorf("signature.NewVerifier(publicHandle) failed: %w", err)
	}

	testInputs := []struct {
		message1 []byte
		message2 []byte
	}{
		{
			message1: []byte("this data needs to be signed"),
			message2: []byte("this data needs to be signed"),
		},
		{
			message1: []byte(""),
			message2: []byte(""),
		},
		{
			message1: []byte(""),
			message2: nil,
		},
		{
			message1: nil,
			message2: []byte(""),
		},
		{
			message1: nil,
			message2: nil,
		},
	}

	for _, ti := range testInputs {
		sig, e := signer.Sign(ti.message1)
		if e != nil {
			return fmt.Errorf("signer.Sign(ti.message1) failed: %w", e)
		}

		if err = verifier.Verify(sig, ti.message2); err != nil {
			return fmt.Errorf("verifier.Verify(sig, ti.message2) failed: %w", err)
		}
	}

	return nil
}
