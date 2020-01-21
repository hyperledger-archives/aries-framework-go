/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package localkms

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/tink"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/secretlock"
)

func TestLocalKMS_NewClient_GetAEAD(t *testing.T) {
	// verify AEAD implements tink.AEAD
	require.Implements(t, (*tink.AEAD)(nil), (*AEAD)(nil))
	// verify localKMSClient implements registry.KMSClient
	require.Implements(t, (*registry.KMSClient)(nil), (*localKMSClient)(nil))

	mockLB := &secretlock.MockSecretLock{
		ValEncrypt: "successEncryption",
		ValDecrypt: "successDecryption",
	}

	cl, err := NewClient(mockLB, "")
	require.Error(t, err)
	require.Empty(t, cl)

	validURI := localKeyURIPrefix + "master/key"
	invalidURI := "bad-prefix://master/key"

	cl, err = NewClient(mockLB, localKeyURIPrefix)
	require.NoError(t, err)
	require.NotEmpty(t, cl)
	require.True(t, cl.Supported(validURI))
	require.False(t, cl.Supported(invalidURI))

	aead, err := cl.GetAEAD(invalidURI)
	require.Error(t, err)
	require.Empty(t, aead)

	aead, err = cl.GetAEAD(validURI)
	require.NoError(t, err)
	require.NotEmpty(t, aead)
}

func TestLocalKMS_EncryptDecrypt(t *testing.T) {
	var flagTests = []struct {
		tcName    string
		encVal    []byte
		errEncVal error
		decVal    []byte
		errDecVal error
	}{
		{
			tcName: "success - valid client, aead, Encrypt and Decrypt",
			encVal: []byte("loremIpsumCiphertext"),
			decVal: []byte("loremIpsumPlainext"),
		},
		{
			tcName:    "error - fail Encrypt/Decrypt",
			errEncVal: fmt.Errorf("encryption failure"),
			errDecVal: fmt.Errorf("decryption failure"),
		},
		{
			tcName: "error - Encrypt fail base64URL.Decode ciphertext",
			encVal: []byte("{}ciphertext"), // {} are illegal base64URL characters
			decVal: []byte("loremIpsumPlaintext"),
		},
		{
			tcName: "error - Decrypt fail base64URL.Decode plaintext",
			encVal: []byte("loremIpsumCiphertext"),
			decVal: []byte("{}plaintext"), // {} are illegal base64URL characters
		},
	}

	validURI := localKeyURIPrefix + "master/key"

	// nolint:scopelint
	for _, tt := range flagTests {
		t.Run(tt.tcName, func(t *testing.T) {
			mockLB := &secretlock.MockSecretLock{
				ErrEncrypt: tt.errEncVal,
				ErrDecrypt: tt.errDecVal,
			}

			if tt.encVal != nil {
				if tt.tcName != "error - Encrypt fail base64URL.Decode ciphertext" {
					mockLB.ValEncrypt = base64.URLEncoding.EncodeToString(tt.encVal)
				} else {
					mockLB.ValEncrypt = string(tt.encVal)
				}
			}

			if tt.decVal != nil {
				if tt.tcName != "error - Decrypt fail base64URL.Decode plaintext" {
					mockLB.ValDecrypt = base64.URLEncoding.EncodeToString(tt.decVal)
				} else {
					mockLB.ValDecrypt = string(tt.decVal)
				}
			}

			localKMSClient, err := NewClient(mockLB, localKeyURIPrefix)
			require.NoError(t, err)
			require.NotEmpty(t, localKMSClient)

			aead, err := localKMSClient.GetAEAD(validURI)
			require.NoError(t, err)
			require.NotEmpty(t, aead)

			// Encrypt() calls secretLock.Encrypt() which is mocked.
			// Only validate if aead returns the mocked value
			ct, err := aead.Encrypt([]byte(""), []byte(""))
			if tt.tcName == "error - Encrypt fail base64URL.Decode ciphertext" {
				require.Nil(t, ct)
				require.EqualError(t, err,
					base64.CorruptInputError(0).Error()) // 0 for index of '{' in "{}ciphertext" test case above
			} else {
				require.EqualValues(t, err, tt.errEncVal)
				require.Equal(t, tt.encVal, ct)
			}

			// same as Decrypt above
			dec, err := aead.Decrypt([]byte(""), []byte(""))
			if tt.tcName == "error - Decrypt fail base64URL.Decode plaintext" {
				require.Nil(t, dec)
				require.EqualError(t, err,
					base64.CorruptInputError(0).Error()) // 0 for index of '{' in "{}plaintext" test case above
			} else {
				require.Equal(t, tt.decVal, dec)
				require.EqualValues(t, err, tt.errDecVal)
			}
		})
	}
}
