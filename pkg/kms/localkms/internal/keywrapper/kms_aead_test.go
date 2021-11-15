/*
 Copyright SecureKey Technologies Inc. All Rights Reserved.

 SPDX-License-Identifier: Apache-2.0
*/

package keywrapper

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/google/tink/go/tink"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/mock/secretlock"
)

func TestLocalKMS_New_AEAD(t *testing.T) {
	// verify LocalAEAD implements tink.AEAD
	require.Implements(t, (*tink.AEAD)(nil), (*LocalAEAD)(nil))

	mockSecLck := &secretlock.MockSecretLock{
		ValEncrypt: "successEncryption",
		ValDecrypt: "successDecryption",
	}

	aeadKW, err := New(mockSecLck, "")
	require.Error(t, err)
	require.Empty(t, aeadKW)

	aeadKW, err = New(mockSecLck, LocalKeyURIPrefix)
	require.Error(t, err)
	require.Empty(t, aeadKW)

	validURIs := []string{
		LocalKeyURIPrefix + "master/key",
		"aws-kms://arn:aws:kms:ca-central-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f",
		"gcp-kms://projects/aries-test-infrastructure/aead-key",
	}
	invalidURIs := []string{
		"://master/key",
		"master/key",
		LocalKeyURIPrefix,
		"aws-kms://",
		"",
	}

	for _, invalidURI := range invalidURIs {
		aeadKW, err = New(mockSecLck, invalidURI)
		require.Error(t, err)
		require.Empty(t, aeadKW)
	}

	for _, validURI := range validURIs {
		aeadKW, err = New(mockSecLck, validURI)
		require.NoError(t, err)
		require.NotEmpty(t, aeadKW)
	}
}

func TestLocalKMS_EncryptDecrypt(t *testing.T) {
	flagTests := []struct {
		tcName    string
		encVal    []byte
		errEncVal error
		decVal    []byte
		errDecVal error
	}{
		{
			tcName: "success - valid aead, Encrypt and Decrypt",
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

	validURI := LocalKeyURIPrefix + "master/key"

	for _, tt := range flagTests {
		t.Run(tt.tcName, func(t *testing.T) {
			mockSecLck := &secretlock.MockSecretLock{
				ErrEncrypt: tt.errEncVal,
				ErrDecrypt: tt.errDecVal,
			}

			if tt.encVal != nil {
				if tt.tcName != "error - Encrypt fail base64URL.Decode ciphertext" {
					mockSecLck.ValEncrypt = base64.URLEncoding.EncodeToString(tt.encVal)
				} else {
					mockSecLck.ValEncrypt = string(tt.encVal)
				}
			}

			if tt.decVal != nil {
				if tt.tcName != "error - Decrypt fail base64URL.Decode plaintext" {
					mockSecLck.ValDecrypt = base64.URLEncoding.EncodeToString(tt.decVal)
				} else {
					mockSecLck.ValDecrypt = string(tt.decVal)
				}
			}

			aeadKW, err := New(mockSecLck, validURI)
			require.NoError(t, err)
			require.NotEmpty(t, aeadKW)

			// Encrypt() calls secretLock.Encrypt() which is mocked.
			// Only validate if aeadKW returns the mocked value
			ct, err := aeadKW.Encrypt([]byte(""), []byte(""))
			if tt.tcName == "error - Encrypt fail base64URL.Decode ciphertext" {
				require.Nil(t, ct)
				require.EqualError(t, err,
					base64.CorruptInputError(0).Error()) // 0 for index of '{' in "{}ciphertext" test case above
			} else {
				require.EqualValues(t, err, tt.errEncVal)
				require.Equal(t, tt.encVal, ct)
			}

			// same as Decrypt above
			dec, err := aeadKW.Decrypt([]byte(""), []byte(""))
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
