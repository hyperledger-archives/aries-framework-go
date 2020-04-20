/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ecdhes

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/stretchr/testify/require"

	ecdhessubtle "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes/subtle"
)

func TestECDHESKeyTemplateTest(t *testing.T) {
	recPubKeys, recKHs := createRecipients(t, 10)
	kt, err := ECDHES256KWAES256GCMKeyTemplateWithRecipients(recPubKeys)
	require.NoError(t, err)

	kh, err := keyset.NewHandle(kt)
	require.NoError(t, err)

	pubKH, err := kh.Public()
	require.NoError(t, err)

	e, err := NewECDHESEncrypt(pubKH)
	require.NoError(t, err)

	pt := []byte("secret message")
	aad := []byte("aad message")

	ct, err := e.Encrypt(pt, aad)
	require.NoError(t, err)
	require.NotEmpty(t, ct)

	// decrypt for all Recipients
	for _, recKH := range recKHs {
		d, er := NewECDHESDecrypt(recKH)
		require.NoError(t, er)

		dpt, er := d.Decrypt(ct, aad)
		require.NoError(t, er)
		require.Equal(t, pt, dpt)
	}
}

// createRecipients and return their public key and keyset.Handle
func createRecipients(t *testing.T, numberOfRecipients int) ([]ecdhessubtle.ECPublicKey, []*keyset.Handle) {
	t.Helper()

	var (
		r   []ecdhessubtle.ECPublicKey
		rKH []*keyset.Handle
	)

	for i := 0; i < numberOfRecipients; i++ {
		mrKey, kh := createAndMarshalRecipient(t)
		ecPubKey := new(ecdhessubtle.ECPublicKey)
		err := json.Unmarshal(mrKey, ecPubKey)
		require.NoError(t, err)

		r = append(r, *ecPubKey)
		rKH = append(rKH, kh)
	}

	return r, rKH
}

// createAndMarshalRecipient creates a new recipient keyset.Handle, extract public key, marshal it and return
// both marshaled public key and original recipient keyset.Handle
func createAndMarshalRecipient(t *testing.T) ([]byte, *keyset.Handle) {
	t.Helper()

	kh, err := keyset.NewHandle(ECDHES256KWAES256GCMKeyTemplate())
	require.NoError(t, err)

	pubKH, err := kh.Public()
	require.NoError(t, err)

	buf := new(bytes.Buffer)
	pubKeyWriter := NewWriter(buf)
	require.NotEmpty(t, pubKeyWriter)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	require.NoError(t, err)

	return buf.Bytes(), kh
}
