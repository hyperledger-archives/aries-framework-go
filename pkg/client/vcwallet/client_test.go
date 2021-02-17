/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	sampleUserID       = "sample-user01"
	toBeImplementedErr = "to be implemented"
)

func TestNew(t *testing.T) {
	vcWalletClient := New(sampleUserID, nil)
	require.NotEmpty(t, vcWalletClient)
}

func TestClient_Export(t *testing.T) {
	vcWalletClient := New(sampleUserID, nil)
	require.NotEmpty(t, vcWalletClient)

	result, err := vcWalletClient.Export("")
	require.Empty(t, result)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Import(t *testing.T) {
	vcWalletClient := New(sampleUserID, nil)
	require.NotEmpty(t, vcWalletClient)

	err := vcWalletClient.Import("", nil)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Add(t *testing.T) {
	vcWalletClient := New(sampleUserID, nil)
	require.NotEmpty(t, vcWalletClient)

	err := vcWalletClient.Add(nil)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Remove(t *testing.T) {
	vcWalletClient := New(sampleUserID, nil)
	require.NotEmpty(t, vcWalletClient)

	err := vcWalletClient.Remove("")
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Get(t *testing.T) {
	vcWalletClient := New(sampleUserID, nil)
	require.NotEmpty(t, vcWalletClient)

	result, err := vcWalletClient.Get("")
	require.Empty(t, result)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Query(t *testing.T) {
	vcWalletClient := New(sampleUserID, nil)
	require.NotEmpty(t, vcWalletClient)

	results, err := vcWalletClient.Query(&QueryParams{})
	require.Empty(t, results)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Issue(t *testing.T) {
	vcWalletClient := New(sampleUserID, nil)
	require.NotEmpty(t, vcWalletClient)

	result, err := vcWalletClient.Issue(nil, &ProofOptions{})
	require.Empty(t, result)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Prove(t *testing.T) {
	vcWalletClient := New(sampleUserID, nil)
	require.NotEmpty(t, vcWalletClient)

	result, err := vcWalletClient.Prove(nil, &ProofOptions{})
	require.Empty(t, result)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}

func TestClient_Verify(t *testing.T) {
	vcWalletClient := New(sampleUserID, nil)
	require.NotEmpty(t, vcWalletClient)

	result, err := vcWalletClient.Verify(nil)
	require.Empty(t, result)
	require.Error(t, err)
	require.EqualError(t, err, toBeImplementedErr)
}
