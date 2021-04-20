/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kmsdidkey

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

func TestBuildDIDKeyByKMSKeyType(t *testing.T) {
	sp := mockstorage.NewMockStoreProvider()
	k := newKMS(t, sp)

	_, ed25519Key, err := k.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	_, bbsKey, err := k.CreateAndExportPubKeyBytes(kms.BLS12381G2Type)
	require.NoError(t, err)

	_, p256IEEEKey, err := k.CreateAndExportPubKeyBytes(kms.ECDSAP256TypeIEEEP1363)
	require.NoError(t, err)

	_, p256DERKey, err := k.CreateAndExportPubKeyBytes(kms.ECDSAP256TypeDER)
	require.NoError(t, err)

	_, p384IEEEKey, err := k.CreateAndExportPubKeyBytes(kms.ECDSAP384TypeIEEEP1363)
	require.NoError(t, err)

	_, p384DERKey, err := k.CreateAndExportPubKeyBytes(kms.ECDSAP384TypeDER)
	require.NoError(t, err)

	_, p521IEEEKey, err := k.CreateAndExportPubKeyBytes(kms.ECDSAP521TypeIEEEP1363)
	require.NoError(t, err)

	_, p521DERKey, err := k.CreateAndExportPubKeyBytes(kms.ECDSAP521TypeDER)
	require.NoError(t, err)

	_, x25519Key, err := k.CreateAndExportPubKeyBytes(kms.X25519ECDHKWType)
	require.NoError(t, err)

	_, p256KWKey, err := k.CreateAndExportPubKeyBytes(kms.NISTP256ECDHKW)
	require.NoError(t, err)

	_, p384KWKey, err := k.CreateAndExportPubKeyBytes(kms.NISTP384ECDHKWType)
	require.NoError(t, err)

	_, p521KWKey, err := k.CreateAndExportPubKeyBytes(kms.NISTP521ECDHKWType)
	require.NoError(t, err)

	tests := []struct {
		name     string
		keyBytes []byte
		keyType  kms.KeyType
	}{
		{
			name:     "test ED25519 key",
			keyBytes: ed25519Key,
			keyType:  kms.ED25519Type,
		},
		{
			name:     "test BLS12381G2 key",
			keyBytes: bbsKey,
			keyType:  kms.BLS12381G2Type,
		},
		{
			name:     "test ECDSAP256TypeIEEEP1363 key",
			keyBytes: p256IEEEKey,
			keyType:  kms.ECDSAP256TypeIEEEP1363,
		},
		{
			name:     "test ECDSAP256TypeDER key",
			keyBytes: p256DERKey,
			keyType:  kms.ECDSAP256TypeDER,
		},
		{
			name:     "test ECDSAP384TypeIEEEP1363 key",
			keyBytes: p384IEEEKey,
			keyType:  kms.ECDSAP384TypeIEEEP1363,
		},
		{
			name:     "test ECDSAP384TypeDER key",
			keyBytes: p384DERKey,
			keyType:  kms.ECDSAP384TypeDER,
		},
		{
			name:     "test ECDSAP521TypeIEEEP1363 key",
			keyBytes: p521IEEEKey,
			keyType:  kms.ECDSAP521TypeIEEEP1363,
		},
		{
			name:     "test ECDSAP521TypeDER key",
			keyBytes: p521DERKey,
			keyType:  kms.ECDSAP521TypeDER,
		},
		{
			name:     "test X25519ECDHKWType key",
			keyBytes: x25519Key,
			keyType:  kms.X25519ECDHKWType,
		},
		{
			name:     "test NISTP256ECDHKW key",
			keyBytes: p256KWKey,
			keyType:  kms.NISTP256ECDHKW,
		},
		{
			name:     "test NISTP384ECDHKW key",
			keyBytes: p384KWKey,
			keyType:  kms.NISTP384ECDHKW,
		},
		{
			name:     "test NISTP521ECDHKW key",
			keyBytes: p521KWKey,
			keyType:  kms.NISTP521ECDHKW,
		},
		{
			name:     "test invalid key",
			keyBytes: []byte{},
			keyType:  "undefined",
		},
		{
			name:     "test invalid X25519 key",
			keyBytes: []byte("wrongKey."),
			keyType:  kms.X25519ECDHKWType,
		},
		{
			name:     "test invalid NISTP256ECDHKW key",
			keyBytes: []byte("wrongKey."),
			keyType:  kms.NISTP256ECDHKW,
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			didKey, err := BuildDIDKeyByKMSKeyType(tc.keyBytes, tc.keyType)
			if tc.name == "test invalid key" {
				require.EqualError(t, err, "keyType 'undefined' does not have a multi-base codec")

				return
			}

			if tc.name == "test invalid X25519 key" {
				require.EqualError(t, err, "buildDIDkeyByKMSKeyType failed to unmarshal key type X25519ECDHKW:"+
					" invalid character 'w' looking for beginning of value")

				return
			}

			if tc.name == "test invalid NISTP256ECDHKW key" {
				require.EqualError(t, err, "buildDIDkeyByKMSKeyType failed to unmarshal key type NISTP256ECDHKW:"+
					" invalid character 'w' looking for beginning of value")

				return
			}

			require.NoError(t, err)
			require.Contains(t, didKey, "did:key:z")
		})
	}
}

func newKMS(t *testing.T, store storage.Provider) kms.KeyManager {
	t.Helper()

	kmsProv := &protocol.MockProvider{
		StoreProvider: store,
		CustomLock:    &noop.NoLock{},
	}

	customKMS, err := localkms.New("local-lock://primary/test/", kmsProv)
	require.NoError(t, err)

	return customKMS
}
