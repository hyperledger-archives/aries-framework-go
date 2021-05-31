/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package aead_test

import (
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/core/registry"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/aead"
	aeadpb "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/proto/aes_cbc_hmac_aead_go_proto"
)

const (
	// AESCBCHMACAEADKeyVersion is the maximal version of AES-CBC-HMAC-AEAD keys that Tink supports.
	AESCBCHMACAEADKeyVersion = 0
	// AESCBCHMACAEADTypeURL is the type URL of AES-CBC-HMAC-AEAD keys that Tink supports.
	AESCBCHMACAEADTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.AesCbcHmacAeadKey"
)

func TestNewKeyMultipleTimes(t *testing.T) {
	keyTemplate := aead.AES128CBCHMACSHA256KeyTemplate()
	aeadKeyFormat := new(aeadpb.AesCbcHmacAeadKeyFormat)
	err := proto.Unmarshal(keyTemplate.Value, aeadKeyFormat)
	require.NoError(t, err, "cannot unmarshal AES128CBCHMACSHA256 key template")

	keyManager, err := registry.GetKeyManager(AESCBCHMACAEADTypeURL)
	require.NoError(t, err, "cannot obtain AES-CBC-HMAC-AEAD key manager: %s", err)

	keys := make(map[string]bool)

	const numTests = 24

	for i := 0; i < numTests/2; i++ {
		k, err := keyManager.NewKey(keyTemplate.Value)
		require.NoError(t, err)

		sk, err := proto.Marshal(k)
		require.NoErrorf(t, err, "cannot serialize key")

		key := new(aeadpb.AesCbcHmacAeadKey)
		err = proto.Unmarshal(sk, key)
		require.NoError(t, err)

		keys[string(key.AesCbcKey.KeyValue)] = true
		keys[string(key.HmacKey.KeyValue)] = true

		require.EqualValuesf(t, 16, len(key.AesCbcKey.KeyValue), fmt.Sprintf("unexpected AES key size, got:"+
			" %d, want: 16", len(key.AesCbcKey.KeyValue)))

		require.EqualValuesf(t, 16, len(key.HmacKey.KeyValue), fmt.Sprintf("unexpected HMAC key size, got:"+
			" %d, want: 32", len(key.HmacKey.KeyValue)))

		require.EqualValues(t, AESCBCHMACAEADKeyVersion, key.Version)
	}

	require.EqualValuesf(t, numTests, len(keys), fmt.Sprintf("unexpected number of keys in set, got: %d, want: %d",
		len(keys), numTests))
}

func TestNewKeyWithCorruptedFormat(t *testing.T) {
	keyTemplate := new(tinkpb.KeyTemplate)

	keyTemplate.TypeUrl = AESCBCHMACAEADTypeURL
	keyTemplate.Value = make([]byte, 128)

	keyManager, err := registry.GetKeyManager(AESCBCHMACAEADTypeURL)
	require.NoError(t, err, "cannot obtain AES-CBC-HMAC-AEAD key manager")

	_, err = keyManager.NewKey(keyTemplate.Value)
	require.Error(t, err, "NewKey got: success, want: error due to corrupted format")

	_, err = keyManager.NewKeyData(keyTemplate.Value)
	require.Error(t, err, "NewKeyData got: success, want: error due to corrupted format")
}
