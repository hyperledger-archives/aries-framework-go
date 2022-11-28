/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didsignjwt

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/test/makemockdoc"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
)

const (
	defaultKID = "#key-1"
	defaultDID = "did:test:foo"
)

func TestSignVerify(t *testing.T) {
	keyManager := createKMS(t)

	cr, e := tinkcrypto.New()
	require.NoError(t, e)

	staticDIDDocs := map[string]*did.Doc{}

	defaultVDR := &mockvdr.MockVDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			if strings.HasPrefix(didID, "did:key:") {
				k := key.New()

				d, err := k.Read(didID)
				if err != nil {
					return nil, err
				}

				return d, nil
			} else if doc, ok := staticDIDDocs[didID]; ok {
				return &did.DocResolution{DIDDocument: doc}, nil
			}

			return nil, fmt.Errorf("did not found")
		},
	}

	doc := makemockdoc.MakeMockDoc(t, keyManager, defaultDID, kms.ECDSAP256TypeIEEEP1363)
	staticDIDDocs[defaultDID] = doc

	testClaims := map[string]interface{}{
		"foo": "bar",
		"baz": []string{"a", "b", "c"},
	}

	t.Run("success", func(t *testing.T) {
		t.Run("use specified key", func(t *testing.T) {
			result, err := SignJWT(nil, testClaims, defaultDID+defaultKID, keyManager, cr, defaultVDR)
			require.NoError(t, err)
			require.NotEmpty(t, result)

			require.NoError(t, VerifyJWT(result, defaultVDR))
		})

		t.Run("default to first assertionmethod", func(t *testing.T) {
			result, err := SignJWT(nil, testClaims, defaultDID, keyManager, cr, defaultVDR)
			require.NoError(t, err)
			require.NotEmpty(t, result)

			require.NoError(t, VerifyJWT(result, defaultVDR))
		})

		t.Run("use EdDSA", func(t *testing.T) {
			mockDoc := makemockdoc.MakeMockDoc(t, keyManager, defaultDID, kms.ED25519Type)

			customVDR := &mockvdr.MockVDRegistry{
				ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
					return &did.DocResolution{DIDDocument: mockDoc}, nil
				},
			}

			result, err := SignJWT(nil, testClaims, defaultDID+defaultKID, keyManager, cr, customVDR)
			require.NoError(t, err)
			require.NotEmpty(t, result)

			require.NoError(t, VerifyJWT(result, customVDR))
		})
	})

	t.Run("failure", func(t *testing.T) {
		t.Run("invalid verification method ID", func(t *testing.T) {
			_, e = SignJWT(nil, testClaims, "did:foo:bar#keyID#extraKeyID", keyManager, cr, defaultVDR)
			require.Error(t, e)
			require.Contains(t, e.Error(), "invalid verification method format")
		})

		t.Run("DID not found in VDR", func(t *testing.T) {
			_, e = SignJWT(nil, testClaims, "did:missing:unknown#keyID", keyManager, cr, defaultVDR)
			require.Error(t, e)
			require.Contains(t, e.Error(), "failed to resolve signing DID")
		})

		t.Run("verification method is invalid", func(t *testing.T) {
			brokenDID := "did:broken:doc"
			brokenVMID := "brokenVM"

			mockDoc := &did.Doc{
				ID: brokenDID,
				VerificationMethod: []did.VerificationMethod{
					{
						ID:   brokenVMID,
						Type: "unsupported type",
					},
				},
			}

			_, e = SignJWT(nil, testClaims, brokenDID+"#"+brokenVMID, keyManager, cr,
				&mockvdr.MockVDRegistry{
					ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
						return &did.DocResolution{DIDDocument: mockDoc}, nil
					},
				})
			require.Error(t, e)
			require.Contains(t, e.Error(), "parsing verification method")
		})

		t.Run("can't get KMS KID", func(t *testing.T) {
			mockDoc := &did.Doc{
				ID: defaultDID,
				VerificationMethod: []did.VerificationMethod{
					{
						ID:   defaultKID,
						Type: ed25519VerificationKey2018,
						// key value is empty, so jwkkid.CreateKID fails
					},
				},
			}

			_, e = SignJWT(nil, testClaims, defaultDID+defaultKID, keyManager, cr,
				&mockvdr.MockVDRegistry{
					ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
						return &did.DocResolution{DIDDocument: mockDoc}, nil
					},
				})
			require.Error(t, e)
			require.Contains(t, e.Error(), "determining the internal ID of the signing key")
		})

		t.Run("key not in KMS", func(t *testing.T) {
			wrongKMS := createKMS(t)

			// signing key is saved in the wrong kms
			mockDoc := makemockdoc.MakeMockDoc(t, wrongKMS, defaultDID, kms.ECDSAP256TypeIEEEP1363)

			// instead of the kms passed in here
			_, e = SignJWT(nil, testClaims, defaultDID, keyManager, cr,
				&mockvdr.MockVDRegistry{
					ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
						return &did.DocResolution{DIDDocument: mockDoc}, nil
					},
				})
			require.Error(t, e)
			require.Contains(t, e.Error(), "fetching the signing key from the key manager")
		})

		t.Run("signing error", func(t *testing.T) {
			kmgr := createKMS(t)

			badPayload := map[string]interface{}{
				"foo": new(chan int), // can't marshal
			}

			mockDoc := makemockdoc.MakeMockDoc(t, kmgr, defaultDID, kms.ECDSAP256TypeIEEEP1363)

			_, e = SignJWT(nil, badPayload, defaultDID+defaultKID, kmgr, cr,
				&mockvdr.MockVDRegistry{
					ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
						return &did.DocResolution{DIDDocument: mockDoc}, nil
					},
				})
			require.Error(t, e)
			require.Contains(t, e.Error(), "signing JWT")
		})

		t.Run("verification error", func(t *testing.T) {
			result, err := SignJWT(nil, testClaims, defaultDID+defaultKID, keyManager, cr, defaultVDR)
			require.NoError(t, err)
			require.NotEmpty(t, result)

			err = VerifyJWT(result, &mockvdr.MockVDRegistry{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "jwt verification failed")
		})
	})
}

func createKMS(t *testing.T) kms.KeyManager {
	kmsStore, err := kms.NewAriesProviderWrapper(mockstorage.NewMockStoreProvider())
	require.NoError(t, err)

	keyManager, err := localkms.New("local-lock://test/master/key/", &kmsProvider{
		kmsStore:          kmsStore,
		secretLockService: &noop.NoLock{},
	})
	require.NoError(t, err)

	return keyManager
}

type kmsProvider struct {
	kmsStore          kms.Store
	secretLockService secretlock.Service
}

func (k *kmsProvider) StorageProvider() kms.Store {
	return k.kmsStore
}

func (k *kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}
