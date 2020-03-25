/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
)

func TestNew(t *testing.T) {
	t.Run("test new command - success", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{
			KMSValue: &mockkms.CloseableKMS{},
		})
		require.NotNil(t, cmd)

		handlers := cmd.GetHandlers()
		require.Equal(t, 1, len(handlers))
	})
}

func TestCreateKeySet(t *testing.T) {
	t.Run("test create key set - success", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{
			KMSValue: &mockkms.CloseableKMS{CreateEncryptionKeyValue: "encryptionKey",
				CreateSigningKeyValue: "signingKey"},
		})
		require.NotNil(t, cmd)

		var getRW bytes.Buffer
		cmdErr := cmd.CreateKeySet(&getRW, nil)
		require.NoError(t, cmdErr)

		response := CreateKeySetResponse{}
		err := json.NewDecoder(&getRW).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.Equal(t, "encryptionKey", response.EncryptionPublicKey)
		require.Equal(t, "signingKey", response.SignaturePublicKey)
	})

	t.Run("test create key set - error", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{
			KMSValue: &mockkms.CloseableKMS{CreateKeyErr: fmt.Errorf("error create key set")},
		})
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err := cmd.CreateKeySet(&b, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error create key set")
	})
}
