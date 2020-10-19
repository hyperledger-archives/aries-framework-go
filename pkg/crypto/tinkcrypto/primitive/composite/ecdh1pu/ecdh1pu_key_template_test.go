/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh1pu

import (
	"testing"

	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
)

func TestECDH1PUKeyTemplateSuccess(t *testing.T) {
	flagTests := []struct {
		tcName    string
		curveType string
		tmplFunc  func() *tinkpb.KeyTemplate
	}{
		{
			tcName:    "create ECDH1PU 256 key templates test",
			curveType: "P-256",
			tmplFunc:  ECDH1PU256KWAES256GCMKeyTemplate,
		},
		{
			tcName:    "create ECDH1PU 384 key templates test",
			curveType: "P-384",
			tmplFunc:  ECDH1PU384KWAES256GCMKeyTemplate,
		},
		{
			tcName:    "create ECDH1PU 521 key templates test",
			curveType: "P-521",
			tmplFunc:  ECDH1PU521KWAES256GCMKeyTemplate,
		},
	}

	for _, tt := range flagTests {
		tc := tt
		t.Run("Test "+tc.tcName, func(t *testing.T) {
			recPubKeys, recKHs := createRecipients(t, tc.curveType, 10)

			kt := tc.tmplFunc()

			// create keyset handle for sender
			kh, err := keyset.NewHandle(kt)
			require.NoError(t, err)

			// add recipients public keys to sender's keyset handle (to prepare for Encryption() call)
			kh, err = AddRecipientsKeys(kh, recPubKeys)
			require.NoError(t, err)

			senderKey, err := keyio.ExtractPrimaryPublicKey(kh)
			require.NoError(t, err)

			pubKH, err := kh.Public()
			require.NoError(t, err)

			e, err := NewECDH1PUEncrypt(pubKH)
			require.NoError(t, err)

			pt := []byte("secret message")
			aad := []byte("aad message")

			ct, err := e.Encrypt(pt, aad)
			require.NoError(t, err)
			require.NotEmpty(t, ct)

			// decrypt for all Recipients
			for _, recKH := range recKHs {
				// first we need to update the recipient's private key protobuf with the sender key (to prepare for
				// Decrypt() call)
				updatedRecKH, er := AddSenderKey(recKH, senderKey)
				require.NoError(t, er)

				d, er := NewECDH1PUDecrypt(updatedRecKH)
				require.NoError(t, er)

				dpt, er := d.Decrypt(ct, aad)
				require.NoError(t, er)
				require.Equal(t, pt, dpt)
			}
		})
	}
}

// createRecipients and return their public key and keyset.Handle.
func createRecipients(t *testing.T, curveType string, nbOfRecipients int) ([]*composite.PublicKey, []*keyset.Handle) {
	t.Helper()

	var (
		r   []*composite.PublicKey
		rKH []*keyset.Handle
	)

	for i := 0; i < nbOfRecipients; i++ {
		ecPubKey, kh := createRecipient(t, curveType)

		r = append(r, ecPubKey)
		rKH = append(rKH, kh)
	}

	return r, rKH
}

// createRecipient creates a new recipient keyset.Handle, extracts public key, marshals it and returns
// both marshalled public key and original recipient keyset.Handle.
func createRecipient(t *testing.T, curveType string) (*composite.PublicKey, *keyset.Handle) {
	t.Helper()

	var tmpl *tinkpb.KeyTemplate

	switch curveType {
	case "P-256":
		tmpl = ECDH1PU256KWAES256GCMKeyTemplate()
	case "P-384":
		tmpl = ECDH1PU384KWAES256GCMKeyTemplate()
	case "P-521":
		tmpl = ECDH1PU521KWAES256GCMKeyTemplate()
	}

	kh, err := keyset.NewHandle(tmpl)
	require.NoError(t, err)

	ecPubKey, err := keyio.ExtractPrimaryPublicKey(kh)
	require.NoError(t, err)

	return ecPubKey, kh
}
