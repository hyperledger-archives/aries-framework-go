/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

func TestSignVerifyKeyTypes(t *testing.T) {
	testCases := []struct {
		name    string
		keyType kms.KeyType
	}{
		{
			"P-256",
			kms.ECDSAP256TypeIEEEP1363,
		},
		{
			"P-384",
			kms.ECDSAP384TypeIEEEP1363,
		},
		{
			"P-521",
			kms.ECDSAP521TypeIEEEP1363,
		},
	}

	data := []byte("abcdefg 1234567 1234567 1234567 1234567 1234567 AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kmsStorage, err := localkms.New("local-lock://test/master/key/", &mockProvider{
				storeProvider: mockstorage.NewMockStoreProvider(),
				secretLock:    &noop.NoLock{},
			})
			require.NoError(t, err)

			cr, err := tinkcrypto.New()
			require.NoError(t, err)

			kid, pkb, err := kmsStorage.CreateAndExportPubKeyBytes(tc.keyType)
			require.NoError(t, err)

			kh, err := kmsStorage.Get(kid)
			require.NoError(t, err)

			pkJWK, err := jwkkid.BuildJWK(pkb, tc.keyType)
			require.NoError(t, err)

			jkBytes, err := pkJWK.PublicKeyBytes()
			require.NoError(t, err)
			require.Equal(t, pkb, jkBytes)

			kh2, err := kmsStorage.PubKeyBytesToHandle(jkBytes, tc.keyType)
			require.NoError(t, err)

			sig, err := cr.Sign(data, kh)
			require.NoError(t, err)

			err = cr.Verify(sig, data, kh2)
			require.NoError(t, err)
		})
	}
}

type mockProvider struct {
	storeProvider storage.Provider
	secretLock    secretlock.Service
}

func (m *mockProvider) StorageProvider() storage.Provider {
	return m.storeProvider
}

func (m *mockProvider) SecretLock() secretlock.Service {
	return m.secretLock
}
