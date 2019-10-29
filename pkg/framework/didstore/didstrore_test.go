/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didstore

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/didstore"
	mockdidstore "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didstore"
)

func TestDIDStore_Put(t *testing.T) {
	t.Run("test invalid did input", func(t *testing.T) {
		didStore := New()
		err := didStore.Put(&did.Doc{ID: "id"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "wrong format did input")
	})

	t.Run("test did method not supported", func(t *testing.T) {
		didStore := New()
		err := didStore.Put(&did.Doc{ID: "did:example:12"})
		require.Error(t, err)
		require.Contains(t, err.Error(), didstore.ErrDidMethodNotSupported.Error())
	})

	t.Run("test success", func(t *testing.T) {
		didStore := New(WithDidMethod(&mockdidstore.MockDidMethod{AcceptValue: true}))
		err := didStore.Put(&did.Doc{ID: "did:example:12"})
		require.NoError(t, err)
	})
}

func TestDIDStore_Get(t *testing.T) {
	t.Run("test invalid did input", func(t *testing.T) {
		didStore := New()
		_, err := didStore.Get("id")
		require.Error(t, err)
		require.Contains(t, err.Error(), "wrong format did input")
	})

	t.Run("test did method not supported", func(t *testing.T) {
		didStore := New()
		_, err := didStore.Get("did:example:12")
		require.Error(t, err)
		require.Contains(t, err.Error(), didstore.ErrDidMethodNotSupported.Error())
	})

	t.Run("test error from did method get", func(t *testing.T) {
		didStore := New(WithDidMethod(&mockdidstore.MockDidMethod{AcceptValue: true, GetErr: fmt.Errorf("get error")}))
		doc, err := didStore.Get("did:example:12")
		require.Error(t, err)
		require.Contains(t, err.Error(), "get error")
		require.Nil(t, doc)
	})

	t.Run("test success", func(t *testing.T) {
		didStore := New(WithDidMethod(&mockdidstore.MockDidMethod{AcceptValue: true, GetValue: &did.Doc{ID: "id"}}))
		doc, err := didStore.Get("did:example:12")
		require.NoError(t, err)
		require.Equal(t, "id", doc.ID)
	})
}
