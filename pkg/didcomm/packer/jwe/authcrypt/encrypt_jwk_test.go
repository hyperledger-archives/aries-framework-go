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

	packer, err := New(mockKMSProvider, XC20P)
	require.NoError(t, err)

	spk, err := packer.generateSPK(nil, nil)
	require.Error(t, err)
	require.Empty(t, spk)

	s, l, m, err := packer.encryptCEK(nil, nil)
	require.Error(t, err)
	require.Empty(t, s)
	require.Empty(t, l)
	require.Empty(t, m)

	s, err = packer.encryptSenderJWK("", "", nil, nil)
	require.Error(t, err)
	require.Empty(t, s)

	// set broken reader
	packer.randReader = &badReader{}

	defer resetRandReader(packer)

	s, err = packer.encryptSenderJWK("", "", nil, nil)
	require.Error(t, err)
	require.Empty(t, s)

	someKey := new([chacha.KeySize]byte)
	spk, err = packer.generateSPK(someKey, nil)
	require.Error(t, err)
	require.Empty(t, spk)

	spk, err = packer.generateSPK(someKey, someKey)
	require.Error(t, err)
	require.Empty(t, spk)

	r, err := packer.encodeRecipient(someKey, someKey, someKey, someKey[:])
	require.Error(t, err)
	require.Empty(t, r)

	s, l, m, err = packer.encryptCEK(someKey[:], someKey[:])
	require.Error(t, err)
	require.Empty(t, s)
	require.Empty(t, l)
	require.Empty(t, m)

	pld, err := packer.Pack([]byte(""), someKey[:], [][]byte{someKey[:]})
	require.Error(t, err)
	require.Empty(t, pld)
}

// Reset random reader to original value
func resetRandReader(p *Packer) {
	p.randReader = rand.Reader
}

type badReader struct{}

func (r *badReader) Read(arr []byte) (int, error) {
	return 0, fmt.Errorf("bad reader")
}
