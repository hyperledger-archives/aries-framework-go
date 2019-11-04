/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	chacha "golang.org/x/crypto/chacha20poly1305"

	mockKMS "github.com/hyperledger/aries-framework-go/pkg/internal/mock/kms"
)

func TestNilEncryptSenderJwk(t *testing.T) {
	mockKMSProvider, err := mockKMS.NewMockProvider()
	require.NoError(t, err)

	crypter, err := New(mockKMSProvider, XC20P)
	require.NoError(t, err)

	spk, err := crypter.generateSPK(nil, nil)
	require.Error(t, err)
	require.Empty(t, spk)

	s, l, m, err := crypter.encryptCEK(nil, nil)
	require.Error(t, err)
	require.Empty(t, s)
	require.Empty(t, l)
	require.Empty(t, m)

	s, err = crypter.encryptSenderJWK("", "", nil, nil)
	require.Error(t, err)
	require.Empty(t, s)

	// set broken reader
	randReader = &badReader{}

	defer resetRandReader()

	s, err = crypter.encryptSenderJWK("", "", nil, nil)
	require.Error(t, err)
	require.Empty(t, s)

	someKey := new([chacha.KeySize]byte)
	spk, err = crypter.generateSPK(someKey, nil)
	require.Error(t, err)
	require.Empty(t, spk)

	spk, err = crypter.generateSPK(someKey, someKey)
	require.Error(t, err)
	require.Empty(t, spk)

	r, err := crypter.encodeRecipient(someKey, someKey, someKey)
	require.Error(t, err)
	require.Empty(t, r)

	s, l, m, err = crypter.encryptCEK(someKey[:], someKey[:])
	require.Error(t, err)
	require.Empty(t, s)
	require.Empty(t, l)
	require.Empty(t, m)

	pld, err := crypter.Pack([]byte(""), someKey[:], [][]byte{someKey[:]})
	require.Error(t, err)
	require.Empty(t, pld)
}

// Reset random reader to original value
func resetRandReader() {
	randReader = rand.Reader
}

type badReader struct{}

func (r *badReader) Read(arr []byte) (int, error) {
	return 0, fmt.Errorf("bad reader")
}
