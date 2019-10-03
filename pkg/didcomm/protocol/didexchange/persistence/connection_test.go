/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package persistence

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
)

func Test_ComputeHash(t *testing.T) {
	h1, err := computeHash([]byte("sample-bytes-123"))
	require.NoError(t, err)
	require.NotEmpty(t, h1)

	h2, err := computeHash([]byte("sample-bytes-321"))
	require.NoError(t, err)
	require.NotEmpty(t, h2)

	h3, err := computeHash([]byte("sample-bytes-123"))
	require.NoError(t, err)
	require.NotEmpty(t, h1)

	require.NotEqual(t, h1, h2)
	require.Equal(t, h1, h3)

	h4, err := computeHash([]byte(""))
	require.Error(t, err)
	require.Empty(t, h4)
}

func TestConnectionRecord_SaveInvitation(t *testing.T) {
	store := &storage.MockStore{Store: make(map[string][]byte)}
	record := NewConnectionRecorder(store)
	require.NotNil(t, record)

	key := "sample-key"
	value := struct {
		Code    int
		Message string
	}{
		Code:    1,
		Message: "sample-msg",
	}

	err := record.SaveInvitation(key, value)
	require.NoError(t, err)

	require.NotEmpty(t, store)

	k, err := computeHash([]byte(key))
	require.NoError(t, err)
	require.NotEmpty(t, k)

	v, err := record.store.Get(k)
	require.NoError(t, err)
	require.NotEmpty(t, v)
}

func TestConnectionRecord_SaveInvitationError(t *testing.T) {
	store := &storage.MockStore{Store: make(map[string][]byte)}
	record := NewConnectionRecorder(store)
	require.NotNil(t, record)

	key := ""
	value := struct {
		Code    int
		Message string
	}{
		Code:    1,
		Message: "sample-msg",
	}

	err := record.SaveInvitation(key, value)
	require.Error(t, err)
	require.Empty(t, store.Store)

	key = "sample-key"
	valueE := struct {
		Code int
		Ch   chan bool
	}{
		Code: 1,
		Ch:   make(chan bool),
	}

	err = record.SaveInvitation(key, valueE)
	require.Error(t, err)
	require.Empty(t, store.Store)
}
