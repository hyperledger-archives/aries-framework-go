/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didexchange

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

func TestCreateNewKeyAndVM(t *testing.T) {
	k := newKMS(t, mockstorage.NewMockStoreProvider())

	t.Run("createNewKeyAndVM success", func(t *testing.T) {
		didDoc := &did.Doc{}

		err := createNewKeyAndVM(didDoc, kms.ED25519, kms.X25519ECDHKWType, k)
		require.NoError(t, err)
		require.Equal(t, ed25519VerificationKey2018, didDoc.VerificationMethod[0].Type)
		require.Equal(t, x25519KeyAgreementKey2019, didDoc.KeyAgreement[0].VerificationMethod.Type)
	})

	t.Run("createNewKeyAndVM invalid keyType export signing key", func(t *testing.T) {
		didDoc := &did.Doc{}

		err := createNewKeyAndVM(didDoc, kms.HMACSHA256Tag256Type, kms.X25519ECDHKWType, k)
		require.EqualError(t, err, "createSigningVM: createAndExportPubKeyBytes: failed to export new public key bytes: "+
			"exportPubKeyBytes: failed to export marshalled key: exportPubKeyBytes: failed to get public keyset "+
			"handle: keyset.Handle: keyset.Handle: keyset contains a non-private key")
		require.Empty(t, didDoc.VerificationMethod)
		require.Empty(t, didDoc.KeyAgreement)
	})
}

func TestCreateSigningVM(t *testing.T) {
	k := newKMS(t, mockstorage.NewMockStoreProvider())

	t.Run("createSigningVM success", func(t *testing.T) {
		svm, err := createSigningVM(k, ed25519VerificationKey2018, kms.ED25519)
		require.NoError(t, err)
		require.NotEmpty(t, svm)
	})

	t.Run("createSigningVM with empty vmType", func(t *testing.T) {
		svm, err := createSigningVM(k, "", kms.ED25519)
		require.EqualError(t, err, "unsupported verification method: ''")
		require.Empty(t, svm)
	})
}

func TestCreateEncryptionVM(t *testing.T) {
	k := newKMS(t, mockstorage.NewMockStoreProvider())

	t.Run("createEncryptionVM success", func(t *testing.T) {
		evm, err := createEncryptionVM(k, x25519KeyAgreementKey2019, kms.X25519ECDHKW)
		require.NoError(t, err)
		require.NotEmpty(t, evm)
	})

	t.Run("createEncryptionVM success with X25519 as jsonwebk2020", func(t *testing.T) {
		evm, err := createEncryptionVM(k, jsonWebKey2020, kms.X25519ECDHKW)
		require.NoError(t, err)
		require.NotEmpty(t, evm)
	})

	t.Run("createEncryptionVM with empty vmType", func(t *testing.T) {
		evm, err := createEncryptionVM(k, "", kms.X25519ECDHKWType)
		require.EqualError(t, err, "unsupported verification method for KeyAgreement: ''")
		require.Empty(t, evm)
	})

	t.Run("createEncryptionVM with unsupported keyType", func(t *testing.T) {
		evm, err := createEncryptionVM(k, jsonWebKey2020, kms.HMACSHA256Tag256Type)
		require.EqualError(t, err, "createEncryptionVM: createAndExportPubKeyBytes: failed to export new public key "+
			"bytes: exportPubKeyBytes: failed to export marshalled key: exportPubKeyBytes: failed to get public "+
			"keyset handle: keyset.Handle: keyset.Handle: keyset contains a non-private key")
		require.Empty(t, evm)
	})
}
