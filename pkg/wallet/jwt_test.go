/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
)

const (
	defaultKID = "#key-1"
	defaultDID = "did:test:foo"
)

func TestWallet_SignJWT(t *testing.T) {
	user := uuid.New().String()

	staticDIDDocs := map[string]*did.Doc{}

	customVDR := &mockvdr.MockVDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			if strings.HasPrefix(didID, "did:key:") {
				k := key.New()

				d, e := k.Read(didID)
				if e != nil {
					return nil, e
				}

				return d, nil
			} else if doc, ok := staticDIDDocs[didID]; ok {
				return &did.DocResolution{DIDDocument: doc}, nil
			}

			return nil, fmt.Errorf("did not found")
		},
	}

	mockctx := newMockProvider(t)
	mockctx.VDRegistryValue = customVDR

	var e error
	mockctx.CryptoValue, e = tinkcrypto.New()
	require.NoError(t, e)

	e = CreateProfile(user, mockctx, WithPassphrase(samplePassPhrase))
	require.NoError(t, e)

	testClaims := map[string]interface{}{
		"foo": "bar",
		"baz": []string{"a", "b", "c"},
	}

	t.Run("success", func(t *testing.T) {
		walletInstance, err := New(user, mockctx)
		require.NotEmpty(t, walletInstance)
		require.NoError(t, err)

		// unlock wallet
		authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
		require.NoError(t, err)
		require.NotEmpty(t, authToken)

		defer walletInstance.Close()

		// import keys manually
		session, err := sessionManager().getSession(authToken)
		require.NotEmpty(t, session)
		require.NoError(t, err)

		kmgr := session.KeyManager
		require.NotEmpty(t, kmgr)

		edPriv := ed25519.PrivateKey(base58.Decode(pkBase58))

		edPub, ok := edPriv.Public().(ed25519.PublicKey)
		require.True(t, ok)

		kmsKID, err := jwkkid.CreateKID(edPub, kms.ED25519Type)
		require.NoError(t, err)

		// nolint: errcheck, gosec
		kmgr.ImportPrivateKey(edPriv, kms.ED25519, kms.WithKeyID(kmsKID))

		result, err := walletInstance.SignJWT(authToken, nil, testClaims, sampleVerificationMethod)
		require.NoError(t, err)
		require.NotEmpty(t, result)

		err = walletInstance.VerifyJWT(result)
		require.NoError(t, err)
	})

	t.Run("failure", func(t *testing.T) {
		t.Run("wallet locked", func(t *testing.T) {
			walletInstance, err := New(user, mockctx)
			require.NotEmpty(t, walletInstance)
			require.NoError(t, err)

			result, err := walletInstance.SignJWT("not auth token", nil, testClaims, defaultDID+defaultKID)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrWalletLocked)
			require.Equal(t, "", result)
		})

		t.Run("didsignjwt handler error", func(t *testing.T) {
			walletInstance, err := New(user, mockctx)
			require.NotEmpty(t, walletInstance)
			require.NoError(t, err)

			// unlock wallet
			authToken, err := walletInstance.Open(WithUnlockByPassphrase(samplePassPhrase))
			require.NoError(t, err)
			require.NotEmpty(t, authToken)

			defer walletInstance.Close()

			_, err = walletInstance.SignJWT(authToken, nil, testClaims, "did:foo:bar#keyID#extraKeyID")
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid verification method format")
		})

		t.Run("verification failure", func(t *testing.T) {
			walletInstance, err := New(user, mockctx)
			require.NotEmpty(t, walletInstance)
			require.NoError(t, err)

			err = walletInstance.VerifyJWT("foo.bar.baz")
			require.Error(t, err)
			require.Contains(t, err.Error(), "jwt verification failed")
		})
	})
}
