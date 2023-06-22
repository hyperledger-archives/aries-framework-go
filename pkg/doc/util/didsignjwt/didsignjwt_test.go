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

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/localkms"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	mockstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mock/storage"
	vdrapi "github.com/hyperledger/aries-framework-go/component/vdr/api"
	"github.com/hyperledger/aries-framework-go/component/vdr/key"
	mockvdr "github.com/hyperledger/aries-framework-go/component/vdr/mock"
	"github.com/hyperledger/aries-framework-go/pkg/internal/test/makemockdoc"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
	"github.com/hyperledger/aries-framework-go/spi/secretlock"
)

const (
	defaultKID                 = "#key-1"
	defaultDID                 = "did:test:foo"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
)

func TestSignVerify(t *testing.T) {
	keyManager := createKMS(t)

	cr, e := tinkcrypto.New()
	require.NoError(t, e)

	staticDIDDocs := map[string]*did.Doc{}

	defaultVDR := &mockvdr.VDRegistry{
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

	doc := makemockdoc.MakeMockDoc(t, keyManager, defaultDID, kmsapi.ECDSAP256TypeIEEEP1363)
	staticDIDDocs[defaultDID] = doc

	testClaims := map[string]interface{}{
		"foo": "bar",
		"baz": []string{"a", "b", "c"},
	}

	t.Run("success", func(t *testing.T) {
		t.Run("use specified key", func(t *testing.T) {
			signingVM, fullKID, err := ResolveSigningVM(defaultDID+defaultKID, defaultVDR)
			require.NoError(t, err)
			require.NotNil(t, signingVM)
			require.Equal(t, defaultDID+defaultKID, fullKID)

			result, err := SignJWT(nil, testClaims, defaultDID+defaultKID, UseDefaultSigner(keyManager, cr), defaultVDR)
			require.NoError(t, err)
			require.NotEmpty(t, result)

			require.NoError(t, VerifyJWT(result, defaultVDR))
		})

		t.Run("default to first assertionmethod", func(t *testing.T) {
			result, err := SignJWT(nil, testClaims, defaultDID, UseDefaultSigner(keyManager, cr), defaultVDR)
			require.NoError(t, err)
			require.NotEmpty(t, result)

			require.NoError(t, VerifyJWT(result, defaultVDR))
		})

		t.Run("use EdDSA", func(t *testing.T) {
			mockDoc := makemockdoc.MakeMockDoc(t, keyManager, defaultDID, kmsapi.ED25519Type)

			customVDR := &mockvdr.VDRegistry{
				ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
					return &did.DocResolution{DIDDocument: mockDoc}, nil
				},
			}

			result, err := SignJWT(nil, testClaims, defaultDID+defaultKID, UseDefaultSigner(keyManager, cr), customVDR)
			require.NoError(t, err)
			require.NotEmpty(t, result)

			require.NoError(t, VerifyJWT(result, customVDR))
		})
	})

	t.Run("failure", func(t *testing.T) {
		t.Run("invalid verification method ID", func(t *testing.T) {
			_, e = SignJWT(nil, testClaims, "did:foo:bar#keyID#extraKeyID", UseDefaultSigner(keyManager, cr), defaultVDR)
			require.Error(t, e)
			require.Contains(t, e.Error(), "invalid verification method format")
		})

		t.Run("DID not found in VDR", func(t *testing.T) {
			_, e = SignJWT(nil, testClaims, "did:missing:unknown#keyID", UseDefaultSigner(keyManager, cr), defaultVDR)
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

			_, e = SignJWT(nil, testClaims, brokenDID+"#"+brokenVMID, UseDefaultSigner(keyManager, cr),
				&mockvdr.VDRegistry{
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

			_, e = SignJWT(nil, testClaims, defaultDID+defaultKID, UseDefaultSigner(keyManager, cr),
				&mockvdr.VDRegistry{
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
			mockDoc := makemockdoc.MakeMockDoc(t, wrongKMS, defaultDID, kmsapi.ECDSAP256TypeIEEEP1363)

			// instead of the kms passed in here
			_, e = SignJWT(nil, testClaims, defaultDID, UseDefaultSigner(keyManager, cr),
				&mockvdr.VDRegistry{
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

			mockDoc := makemockdoc.MakeMockDoc(t, kmgr, defaultDID, kmsapi.ECDSAP256TypeIEEEP1363)

			_, e = SignJWT(nil, badPayload, defaultDID+defaultKID, UseDefaultSigner(kmgr, cr),
				&mockvdr.VDRegistry{
					ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
						return &did.DocResolution{DIDDocument: mockDoc}, nil
					},
				})
			require.Error(t, e)
			require.Contains(t, e.Error(), "signing JWT")
		})

		t.Run("verification error", func(t *testing.T) {
			result, err := SignJWT(nil, testClaims, defaultDID+defaultKID, UseDefaultSigner(keyManager, cr), defaultVDR)
			require.NoError(t, err)
			require.NotEmpty(t, result)

			err = VerifyJWT(result, &mockvdr.VDRegistry{})
			require.Error(t, err)
			require.Contains(t, err.Error(), "jwt verification failed")
		})
	})
}

func createKMS(t *testing.T) kmsapi.KeyManager {
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
	kmsStore          kmsapi.Store
	secretLockService secretlock.Service
}

func (k *kmsProvider) StorageProvider() kmsapi.Store {
	return k.kmsStore
}

func (k *kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}
