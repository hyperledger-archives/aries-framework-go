/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
)

func TestNew(t *testing.T) {
	t.Run("test new command - success", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{
			KMSValue: &mockkms.KeyManager{},
		})
		require.NotNil(t, cmd)

		handlers := cmd.GetHandlers()
		require.Equal(t, 1, len(handlers))
	})

	t.Run("test new command - error from export public key", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{
			KMSValue: &mockkms.KeyManager{},
		})
		require.NotNil(t, cmd)

		_, err := cmd.exportPubKeyBytes("id")
		require.Error(t, err)
		require.Contains(t, err.Error(), "kms is not LocalKMS type")
	})
}

func TestCreateKeySet(t *testing.T) {
	t.Run("test create key set - success", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{
			KMSValue: &mockkms.KeyManager{CreateKeyID: "keyID"},
		})
		require.NotNil(t, cmd)

		cmd.exportPubKeyBytes = func(id string) ([]byte, error) {
			return []byte("publicKey"), nil
		}

		req := CreateKeySetRequest{
			KeyType: "ED25519",
		}
		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		var getRW bytes.Buffer
		cmdErr := cmd.CreateKeySet(&getRW, bytes.NewBuffer(reqBytes))
		require.NoError(t, cmdErr)

		response := CreateKeySetResponse{}
		err = json.NewDecoder(&getRW).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.Equal(t, "keyID", response.KeyID)
		require.Equal(t, base64.RawURLEncoding.EncodeToString([]byte("publicKey")), response.PublicKey)
	})

	t.Run("test create key set - error", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{
			KMSValue: &mockkms.KeyManager{CreateKeyErr: fmt.Errorf("error create key set")},
		})
		require.NotNil(t, cmd)

		req := CreateKeySetRequest{
			KeyType: "ED25519",
		}
		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.CreateKeySet(&b, bytes.NewBuffer(reqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "error create key set")
	})

	t.Run("test create key set - error request decode", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{})
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err := cmd.CreateKeySet(&b, bytes.NewBuffer(nil))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed request decode")
	})

	t.Run("test create key set - error key type is empty", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{})
		require.NotNil(t, cmd)

		reqBytes, err := json.Marshal(CreateKeySetRequest{})
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.CreateKeySet(&b, bytes.NewBuffer(reqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), errEmptyKeyType)
	})

	t.Run("test create key set - error from export public key", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{
			KMSValue: &mockkms.KeyManager{CreateKeyID: "keyID"},
		})
		require.NotNil(t, cmd)

		cmd.exportPubKeyBytes = func(id string) ([]byte, error) {
			return nil, fmt.Errorf("error export public key")
		}

		reqBytes, err := json.Marshal(CreateKeySetRequest{KeyType: "invalid"})
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.CreateKeySet(&b, bytes.NewBuffer(reqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "error export public key")
	})
}
