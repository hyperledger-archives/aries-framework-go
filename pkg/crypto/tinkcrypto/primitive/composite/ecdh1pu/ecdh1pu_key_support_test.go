/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdh1pu

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/signature"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
)

func TestAddMultiRecipientsKeys(t *testing.T) {
	recKH1, err := keyset.NewHandle(ECDH1PU256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	recPubKey1, err := keyio.ExtractPrimaryPublicKey(recKH1)
	require.NoError(t, err)

	recKH2, err := keyset.NewHandle(ECDH1PU256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	recPubKey2, err := keyio.ExtractPrimaryPublicKey(recKH2)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ECDH1PU256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	senderPubKey, err := keyio.ExtractPrimaryPublicKey(senderKH)
	require.NoError(t, err)

	senderKH, err = AddRecipientsKeys(senderKH, []*composite.PublicKey{recPubKey1, recPubKey2})
	require.NoError(t, err)

	senderPubKH, err := senderKH.Public()
	require.NoError(t, err)

	e, err := NewECDH1PUEncrypt(senderPubKH)
	require.NoError(t, err)

	pt := []byte("plaintext message")
	aad := []byte("aad message")

	ct, err := e.Encrypt(pt, aad)
	require.NoError(t, err)

	recKH1, err = AddSenderKey(recKH1, senderPubKey)
	require.NoError(t, err)

	d1, err := NewECDH1PUDecrypt(recKH1)
	require.NoError(t, err)

	dpt1, err := d1.Decrypt(ct, aad)
	require.NoError(t, err)

	require.EqualValues(t, dpt1, pt)

	recKH2, err = AddSenderKey(recKH2, senderPubKey)
	require.NoError(t, err)

	d2, err := NewECDH1PUDecrypt(recKH2)
	require.NoError(t, err)

	dpt2, err := d2.Decrypt(ct, aad)
	require.NoError(t, err)

	require.EqualValues(t, dpt2, pt)
}

func TestAddSingleRecipientKeys(t *testing.T) {
	recKH, err := keyset.NewHandle(ECDH1PU256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	recPubKey, err := keyio.ExtractPrimaryPublicKey(recKH)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ECDH1PU256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	senderPubKey, err := keyio.ExtractPrimaryPublicKey(senderKH)
	require.NoError(t, err)

	senderKH, err = AddRecipientsKeys(senderKH, []*composite.PublicKey{recPubKey})
	require.NoError(t, err)

	senderPubKH, err := senderKH.Public()
	require.NoError(t, err)

	e, err := NewECDH1PUEncrypt(senderPubKH)
	require.NoError(t, err)

	pt := []byte("plaintext message")

	// single recipient requires a base64url encode JSON format (or empty JSON string)
	aad := []byte("{\"someKey\":\"aad message\"}")

	ct, err := e.Encrypt(pt, []byte(base64.RawURLEncoding.EncodeToString(aad)))
	require.NoError(t, err)

	recKH, err = AddSenderKey(recKH, senderPubKey)
	require.NoError(t, err)

	d, err := NewECDH1PUDecrypt(recKH)
	require.NoError(t, err)

	encData := &composite.EncryptedData{}
	err = json.Unmarshal(ct, encData)
	require.NoError(t, err)

	// single recipient is a special case where the AAD is merged and is available in encData.SingleRecipientAAD
	dpt, err := d.Decrypt(ct, encData.SingleRecipientAAD)
	require.NoError(t, err)

	require.EqualValues(t, dpt, pt)

	_, err = AddSenderKey(recKH, &composite.PublicKey{
		Curve: "BADCurve",
	})
	require.EqualError(t, err, "AddSenderKey: failed to convert senderKey to proto: curve BADCurve not "+
		"supported")

	_, err = AddSenderKey(recKH, &composite.PublicKey{
		Curve: "P-256",
		Type:  "BADType",
	})
	require.EqualError(t, err, "AddSenderKey: failed to convert senderKey to proto: key type BADType not "+
		"supported")
}

func TestAddRecipientsKeys(t *testing.T) {
	recKH, err := keyset.NewHandle(ECDH1PU256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	recPubKey, err := keyio.ExtractPrimaryPublicKey(recKH)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ECDH1PU256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	senderPubKH, err := senderKH.Public()
	require.NoError(t, err)

	_, err = AddRecipientsKeys(senderPubKH, []*composite.PublicKey{recPubKey})
	require.EqualError(t, err, "AddRecipientsKeys: keyset.Handle points to a public key. It must point to a "+
		"priviate key")

	senderKH, err = keyset.NewHandle(signature.ECDSAP256KeyTemplate())
	require.NoError(t, err)

	senderKH, err = AddRecipientsKeys(senderKH, []*composite.PublicKey{recPubKey})
	require.EqualError(t, err, "AddRecipientsKeys: extract keyset failed: AddRecipientsKeys: primary key not "+
		"found in keyset")

	senderKH, err = AddRecipientsKeys(senderKH, []*composite.PublicKey{{
		Curve: "BADCurve",
	}})
	require.EqualError(t, err, "AddRecipientsKeys: failed to convert recipient to proto: curve BADCurve not "+
		"supported")

	_, err = AddRecipientsKeys(senderKH, []*composite.PublicKey{{
		Curve: "P-256",
		Type:  "BADType",
	}})
	require.EqualError(t, err, "AddRecipientsKeys: failed to convert recipient to proto: key type BADType not "+
		"supported")
}

func TestExtractKeySetError(t *testing.T) {
	kh, err := keyset.NewHandle(ECDH1PU256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	lock := &writerLock{}

	newErr := errors.New("failed to write")
	_, _, err = extractKeySet(kh, &errorWriter{
		errVal:    newErr,
		encErrVal: newErr,
	},
		lock, "someFn")
	require.EqualError(t, err, "someFn: failed to write recipient keyset: failed to write")

	_, _, err = extractKeySet(kh, &errorWriter{}, lock, "someFn")
	require.EqualError(t, err, "someFn: invalid writer instance")
}

type errorWriter struct {
	errVal    error
	encErrVal error
}

func (w *errorWriter) Write(_ *tinkpb.Keyset) error {
	return w.errVal
}

func (w *errorWriter) WriteEncrypted(_ *tinkpb.EncryptedKeyset) error {
	return w.encErrVal
}
