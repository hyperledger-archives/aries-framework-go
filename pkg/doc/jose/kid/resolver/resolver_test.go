/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolver

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	commonpb "github.com/google/tink/go/proto/common_go_proto"
	"github.com/stretchr/testify/require"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

func TestResolveDIDKey(t *testing.T) {
	didKeyP256 := "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"

	didKeyResolver := &DIDKeyResolver{}

	key, err := didKeyResolver.Resolve(didKeyP256)
	require.NoError(t, err)
	require.NotEmpty(t, key)
	require.Equal(t, commonpb.EllipticCurveType_NIST_P256.String(), key.Curve)
	require.Equal(t, "EC", key.Type)
}

func TestResolveStoreKey(t *testing.T) {
	kid := "key-1"
	expectedKey := &cryptoapi.PublicKey{
		KID:   kid,
		X:     []byte("x"),
		Y:     []byte("y"),
		Curve: "P-521",
		Type:  "EC",
	}

	mKey, err := json.Marshal(expectedKey)
	require.NoError(t, err)

	store := &mockstorage.MockStore{Store: make(map[string]mockstorage.DBEntry)}

	t.Run("resolve success", func(t *testing.T) {
		err = store.Put(kid, mKey)
		require.NoError(t, err)

		storeKeyResolver := &StoreResolver{Store: store}

		key, e := storeKeyResolver.Resolve(kid)
		require.NoError(t, e)
		require.EqualValues(t, expectedKey, key)
	})

	t.Run("resolve fail with Unmarshal error", func(t *testing.T) {
		err = store.Put(kid, []byte("*"))
		require.NoError(t, err)

		storeKeyResolver := &StoreResolver{Store: store}

		key, e := storeKeyResolver.Resolve(kid)
		require.EqualError(t, e, "storeResolver: failed to unmarshal public key from DB: invalid character "+
			"'*' looking for beginning of value")
		require.Empty(t, key)
	})

	t.Run("resolve fail with Get error", func(t *testing.T) {
		getFailErr := "get Fail"
		failStore := &mockstorage.MockStore{ErrGet: errors.New(getFailErr)}
		storeKeyResolver := &StoreResolver{Store: failStore}

		key, e := storeKeyResolver.Resolve(kid)
		require.EqualError(t, e, fmt.Sprintf("storeResolver: failed to resolve kid from store: %s", getFailErr))
		require.Empty(t, key)
	})
}
