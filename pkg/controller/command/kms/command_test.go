/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
)

func TestNew(t *testing.T) {
	t.Run("test new command - success", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{
			KMSValue: &mockkms.KeyManager{},
		})
		require.NotNil(t, cmd)

		handlers := cmd.GetHandlers()
		require.Equal(t, 2, len(handlers))
	})

	t.Run("test new command - error from import key", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{
			KMSValue: &mockkms.KeyManager{ImportPrivateKeyErr: fmt.Errorf("error import priv key")},
		})
		require.NotNil(t, cmd)

		_, _, err := cmd.importKey("", "")
		require.EqualError(t, err, "error import priv key")
	})
}

func TestCreateKeySet(t *testing.T) {
	t.Run("test create key set - success", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{
			KMSValue: &mockkms.KeyManager{CrAndExportPubKeyID: "keyID", CrAndExportPubKeyValue: []byte("publicKey")},
		})
		require.NotNil(t, cmd)

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
			KMSValue: &mockkms.KeyManager{CrAndExportPubKeyErr: fmt.Errorf("error create key set")},
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
			KMSValue: &mockkms.KeyManager{
				CrAndExportPubKeyErr: fmt.Errorf("error export public key"),
			},
		})
		require.NotNil(t, cmd)

		reqBytes, err := json.Marshal(CreateKeySetRequest{KeyType: "invalid"})
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.CreateKeySet(&b, bytes.NewBuffer(reqBytes))
		require.EqualError(t, err, "error export public key")
	})
}

func TestImportKey(t *testing.T) {
	t.Run("test import key - success", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{})
		require.NotNil(t, cmd)

		cmd.importKey = func(privKey interface{}, kt kms.KeyType,
			opts ...kms.PrivateKeyOpts) (string, interface{}, error) {
			return "", nil, nil
		}

		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		j := jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key:       privateKey,
				KeyID:     "kid",
				Algorithm: "EdDSA",
			},
		}

		jwkBytes, err := json.Marshal(&j)
		require.NoError(t, err)

		var getRW bytes.Buffer
		cmdErr := cmd.ImportKey(&getRW, bytes.NewBuffer(jwkBytes))
		require.NoError(t, cmdErr)

		p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		j = jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key:       p256Key,
				KeyID:     "kid",
				Algorithm: "ECDSA",
				Use:       "enc",
			},
		}

		jwkBytes, err = json.Marshal(&j)
		require.NoError(t, err)

		cmdErr = cmd.ImportKey(&getRW, bytes.NewBuffer(jwkBytes))
		require.NoError(t, cmdErr)
	})

	t.Run("test import key - error", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{})
		require.NotNil(t, cmd)

		cmd.importKey = func(privKey interface{}, kt kms.KeyType,
			opts ...kms.PrivateKeyOpts) (string, interface{}, error) {
			return "", nil, fmt.Errorf("failed to import key")
		}

		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		j := jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key:       privateKey,
				KeyID:     "kid",
				Algorithm: "EdDSA",
			},
		}

		jwkBytes, err := json.Marshal(&j)
		require.NoError(t, err)

		var getRW bytes.Buffer
		cmdErr := cmd.ImportKey(&getRW, bytes.NewBuffer(jwkBytes))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "failed to import key")
	})

	t.Run("test import key - unsupported key", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{})
		require.NotNil(t, cmd)

		cmd.importKey = func(privKey interface{}, kt kms.KeyType,
			opts ...kms.PrivateKeyOpts) (string, interface{}, error) {
			return "", nil, nil
		}

		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		j := jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key:       privateKey,
				KeyID:     "kid",
				Algorithm: "EdDSA",
			},
		}

		jwkBytes, err := json.Marshal(&j)
		require.NoError(t, err)

		var getRW bytes.Buffer
		cmdErr := cmd.ImportKey(&getRW, bytes.NewBuffer(jwkBytes))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "import key type not supported P-521")
	})

	t.Run("test import key - jwk without keyID", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{})
		require.NotNil(t, cmd)

		cmd.importKey = func(privKey interface{}, kt kms.KeyType,
			opts ...kms.PrivateKeyOpts) (string, interface{}, error) {
			return "", nil, nil
		}

		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		j := jwk.JWK{
			JSONWebKey: jose.JSONWebKey{
				Key:       privateKey,
				Algorithm: "EdDSA",
			},
		}

		jwkBytes, err := json.Marshal(&j)
		require.NoError(t, err)

		var getRW bytes.Buffer
		cmdErr := cmd.ImportKey(&getRW, bytes.NewBuffer(jwkBytes))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "key id is mandatory")
	})

	t.Run("test import key - error request decode", func(t *testing.T) {
		cmd := New(&mockprovider.Provider{})
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err := cmd.ImportKey(&b, bytes.NewBuffer(nil))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed request decode")
	})
}
