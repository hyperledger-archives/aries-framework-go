/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mem_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	storagetest "github.com/hyperledger/aries-framework-go/test/component/storage"
)

func TestCommon(t *testing.T) {
	provider := mem.NewProvider()

	storagetest.TestAll(t, provider)
}

func TestMemIterator(t *testing.T) {
	provider := mem.NewProvider()

	store, err := provider.OpenStore("TestStore")
	require.NoError(t, err)

	iterator, err := store.Query("TagName1;TagValue2")
	require.NoError(t, err)

	key, err := iterator.Key()
	require.EqualError(t, err, "iterator is exhausted")
	require.Empty(t, key)

	value, err := iterator.Value()
	require.EqualError(t, err, "iterator is exhausted")
	require.Nil(t, value)

	tags, err := iterator.Tags()
	require.EqualError(t, err, "iterator is exhausted")
	require.Nil(t, tags)
}
