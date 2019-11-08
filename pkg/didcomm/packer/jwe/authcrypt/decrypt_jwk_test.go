/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	chacha "golang.org/x/crypto/chacha20poly1305"

	mockkms "github.com/hyperledger/aries-framework-go/pkg/internal/mock/kms"
)

//nolint:lll
func TestNilDecryptSenderJwk(t *testing.T) {
	mockKMSProvider, err := mockkms.NewMockProvider()
	require.NoError(t, err)

	packer, err := New(mockKMSProvider, XC20P)
	require.NoError(t, err)

	spk, err := packer.decryptSPK(nil, "!-.t.t.t.t")
	require.Error(t, err)
	require.Empty(t, spk)

	spk, err = packer.decryptSPK(nil, "eyJ0eXAiOiJqb3NlIiwiY3R5IjoiandrK2pzb24iLCJhbGciOiJFQ0RILUVTK1hDMjBQS1ciLCJlbmMiOiJYQzIwUCIsIml2IjoiNWhwNEVrWGtqSHR0SFlmY1IySXQ4d2dnZndjanNQaWwiLCJ0YWciOiJuMjg1OGplTXhZVE0tYzRZc2J0ZlBRIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJ3OW1EZ1FENnJVdWkyLVMyRjV6SVNqZXBua1FOZWEwMGtvTnRBOUhEeUIwIn19.!-.t.t.t")
	require.Error(t, err)
	require.Empty(t, spk)

	spk, err = packer.decryptSPK(nil, "eyJ0eXAiOiJqb3NlIiwiY3R5IjoiandrK2pzb24iLCJhbGciOiJFQ0RILUVTK1hDMjBQS1ciLCJlbmMiOiJYQzIwUCIsIml2IjoiNWhwNEVrWGtqSHR0SFlmY1IySXQ4d2dnZndjanNQaWwiLCJ0YWciOiJuMjg1OGplTXhZVE0tYzRZc2J0ZlBRIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJ3OW1EZ1FENnJVdWkyLVMyRjV6SVNqZXBua1FOZWEwMGtvTnRBOUhEeUIwIn19.U-AXyneFJ5x4QayrZ3GcuDCg1yHYHC9Kn1s8gtd7O4c.!-.t.t")
	require.Error(t, err)
	require.Empty(t, spk)

	spk, err = packer.decryptSPK(nil, "eyJ0eXAiOiJqb3NlIiwiY3R5IjoiandrK2pzb24iLCJhbGciOiJFQ0RILUVTK1hDMjBQS1ciLCJlbmMiOiJYQzIwUCIsIml2IjoiNWhwNEVrWGtqSHR0SFlmY1IySXQ4d2dnZndjanNQaWwiLCJ0YWciOiJuMjg1OGplTXhZVE0tYzRZc2J0ZlBRIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJ3OW1EZ1FENnJVdWkyLVMyRjV6SVNqZXBua1FOZWEwMGtvTnRBOUhEeUIwIn19.U-AXyneFJ5x4QayrZ3GcuDCg1yHYHC9Kn1s8gtd7O4c.aigDJrko05dw-9Hk4LQbfOCCG9Dzskw6.!-.t")
	require.Error(t, err)
	require.Empty(t, spk)

	spk, err = packer.decryptSPK(nil, "eyJ0eXAiOiJqb3NlIiwiY3R5IjoiandrK2pzb24iLCJhbGciOiJFQ0RILUVTK1hDMjBQS1ciLCJlbmMiOiJYQzIwUCIsIml2IjoiNWhwNEVrWGtqSHR0SFlmY1IySXQ4d2dnZndjanNQaWwiLCJ0YWciOiJuMjg1OGplTXhZVE0tYzRZc2J0ZlBRIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJ3OW1EZ1FENnJVdWkyLVMyRjV6SVNqZXBua1FOZWEwMGtvTnRBOUhEeUIwIn19.U-AXyneFJ5x4QayrZ3GcuDCg1yHYHC9Kn1s8gtd7O4c.aigDJrko05dw-9Hk4LQbfOCCG9Dzskw6.tY10QY9fXvqV_vfhzBKkqw.!-")
	require.Error(t, err)
	require.Empty(t, spk)

	headersJSON := &recipientSPKJWEHeaders{EPK: jwk{
		X: "test",
	}}
	someKey := new([chacha.KeySize]byte)
	spk, err = packer.decryptJWKSharedKey([]byte(""), headersJSON, someKey[:])
	require.Error(t, err)
	require.Empty(t, spk)

	headersJSON.EPK.X = "!-"
	spk, err = packer.decryptJWKSharedKey([]byte(""), headersJSON, someKey[:])
	require.Error(t, err)
	require.Empty(t, spk)

	headersJSON.EPK.X = "test"
	headersJSON.Tag = "!-"

	spk, err = packer.decryptJWKSharedKey([]byte(""), headersJSON, someKey[:])
	require.Error(t, err)
	require.Empty(t, spk)

	headersJSON.Tag = "test"
	headersJSON.IV = "!-"
	spk, err = packer.decryptJWKSharedKey([]byte(""), headersJSON, someKey[:])
	require.Error(t, err)
	require.Empty(t, spk)

	headersJSON.IV = "aigDJrko05dw-9Hk4LQbfOCCG9Dzskw6"

	// set broken reader
	packer.randReader = &badReader{}

	defer resetRandReader(packer)

	nonce, err := base64.RawURLEncoding.DecodeString(headersJSON.IV)
	require.NoError(t, err)

	spk, err = packer.decryptSenderJWK(nonce, nil, nil, nil, nil)
	require.Error(t, err)
	require.Empty(t, spk)

	spk, err = packer.decryptSenderJWK(nonce, someKey[:], nil, nil, nil)
	require.Error(t, err)
	require.Empty(t, spk)
}
