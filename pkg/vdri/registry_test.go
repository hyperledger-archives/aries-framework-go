/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdri

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/internal/mock/kms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/internal/mock/vdri"
)

func TestRegistry_New(t *testing.T) {
	t.Run("test new success", func(t *testing.T) {
		registry := New(&mockprovider.Provider{})
		require.NotNil(t, registry)
	})
	t.Run("test new with opts success", func(t *testing.T) {
		const sampleSvcType = "sample-svc-type"
		const sampleSvcEndpoint = "sample-svc-endpoint"
		registry := New(&mockprovider.Provider{},
			WithDefaultServiceEndpoint(sampleSvcEndpoint), WithDefaultServiceType(sampleSvcType))
		require.NotNil(t, registry)
		require.Equal(t, sampleSvcEndpoint, registry.defServiceEndpoint)
		require.Equal(t, sampleSvcType, registry.defServiceType)
	})
}

func TestRegistry_Close(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		registry := New(&mockprovider.Provider{})
		require.NoError(t, registry.Close())
	})
	t.Run("test error", func(t *testing.T) {
		registry := New(&mockprovider.Provider{},
			WithVDRI(&mockvdri.MockVDRI{CloseErr: fmt.Errorf("close error")}))
		err := registry.Close()
		require.Error(t, err)
		require.Contains(t, err.Error(), "close error")
	})
}

func TestRegistry_Resolve(t *testing.T) {
	t.Run("test invalid did input", func(t *testing.T) {
		registry := New(&mockprovider.Provider{})
		doc, err := registry.Resolve("id")
		require.Error(t, err)
		require.Contains(t, err.Error(), "wrong format did input")
		require.Nil(t, doc)
	})

	t.Run("test did method not supported", func(t *testing.T) {
		registry := New(&mockprovider.Provider{}, WithVDRI(&mockvdri.MockVDRI{AcceptValue: false}))
		doc, err := registry.Resolve("1:id:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "did method id not supported for vdri")
		require.Nil(t, doc)
	})

	t.Run("test DID not found", func(t *testing.T) {
		registry := New(&mockprovider.Provider{}, WithVDRI(&mockvdri.MockVDRI{
			AcceptValue: true, ReadFunc: func(didID string, opts ...vdriapi.ResolveOpts) (*did.Doc, error) {
				return nil, vdriapi.ErrNotFound
			}}))
		doc, err := registry.Resolve("1:id:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), vdriapi.ErrNotFound.Error())
		require.Nil(t, doc)
	})

	t.Run("test error from resolve did", func(t *testing.T) {
		registry := New(&mockprovider.Provider{}, WithVDRI(&mockvdri.MockVDRI{
			AcceptValue: true, ReadFunc: func(didID string, opts ...vdriapi.ResolveOpts) (*did.Doc, error) {
				return nil, fmt.Errorf("read error")
			}}))
		doc, err := registry.Resolve("1:id:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "read error")
		require.Nil(t, doc)
	})

	t.Run("test ResultType", func(t *testing.T) {
		registry := New(&mockprovider.Provider{}, WithVDRI(&mockvdri.MockVDRI{AcceptValue: true}))
		doc, err := registry.Resolve("1:id:123", vdriapi.WithResultType(vdriapi.ResolutionResult))
		require.Error(t, err)
		require.Contains(t, err.Error(), "result type 'resolution-result' not supported")
		require.Nil(t, doc)
	})

	t.Run("test opts passed", func(t *testing.T) {
		registry := New(&mockprovider.Provider{}, WithVDRI(&mockvdri.MockVDRI{
			AcceptValue: true, ReadFunc: func(didID string, opts ...vdriapi.ResolveOpts) (*did.Doc, error) {
				resolveOpts := &vdriapi.ResolveDIDOpts{}
				// Apply options
				for _, opt := range opts {
					opt(resolveOpts)
				}
				require.Equal(t, "1", resolveOpts.VersionID)
				return nil, nil
			}}))
		_, err := registry.Resolve("1:id:123", vdriapi.WithVersionID("1"))
		require.NoError(t, err)
	})

	t.Run("test success", func(t *testing.T) {
		registry := New(&mockprovider.Provider{}, WithVDRI(&mockvdri.MockVDRI{AcceptValue: true}))
		_, err := registry.Resolve("1:id:123")
		require.NoError(t, err)
	})
}

func TestRegistry_Store(t *testing.T) {
	t.Run("test invalid did input", func(t *testing.T) {
		registry := New(&mockprovider.Provider{})
		err := registry.Store(&did.Doc{ID: "id"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "wrong format did input")
	})

	t.Run("test did method not supported", func(t *testing.T) {
		registry := New(&mockprovider.Provider{}, WithVDRI(&mockvdri.MockVDRI{AcceptValue: false}))
		err := registry.Store(&did.Doc{ID: "1:id:123"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "did method id not supported for vdri")
	})

	t.Run("test success", func(t *testing.T) {
		registry := New(&mockprovider.Provider{}, WithVDRI(&mockvdri.MockVDRI{AcceptValue: true}))
		err := registry.Store(&did.Doc{ID: "1:id:123"})
		require.NoError(t, err)
	})
}

func TestRegistry_Create(t *testing.T) {
	t.Run("test error from create key", func(t *testing.T) {
		registry := New(&mockprovider.Provider{
			KMSValue: &mockkms.CloseableKMS{CreateKeyErr: fmt.Errorf("create key error")}})
		doc, err := registry.Create("1:id:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "create key error")
		require.Nil(t, doc)
	})
	t.Run("test did method not supported", func(t *testing.T) {
		registry := New(&mockprovider.Provider{KMSValue: &mockkms.CloseableKMS{}},
			WithVDRI(&mockvdri.MockVDRI{AcceptValue: false}))
		doc, err := registry.Create("id")
		require.Error(t, err)
		require.Contains(t, err.Error(), "did method id not supported for vdri")
		require.Nil(t, doc)
	})
	t.Run("test opts is passed", func(t *testing.T) {
		registry := New(&mockprovider.Provider{KMSValue: &mockkms.CloseableKMS{}},
			WithVDRI(&mockvdri.MockVDRI{AcceptValue: true,
				BuildFunc: func(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (doc *did.Doc, e error) {
					docOpts := &vdriapi.CreateDIDOpts{}
					// Apply options
					for _, opt := range opts {
						opt(docOpts)
					}
					require.Equal(t, "key1", docOpts.KeyType)
					return &did.Doc{ID: "1:id:123"}, nil
				}}))
		_, err := registry.Create("id", vdriapi.WithKeyType("key1"))
		require.NoError(t, err)
	})
	t.Run("test error from build doc", func(t *testing.T) {
		registry := New(&mockprovider.Provider{KMSValue: &mockkms.CloseableKMS{}},
			WithVDRI(&mockvdri.MockVDRI{AcceptValue: true,
				BuildFunc: func(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (doc *did.Doc, e error) {
					return nil, fmt.Errorf("build did error")
				}}))
		doc, err := registry.Create("id")
		require.Error(t, err)
		require.Contains(t, err.Error(), "build did error")
		require.Nil(t, doc)
	})
	t.Run("test error from store doc", func(t *testing.T) {
		registry := New(&mockprovider.Provider{KMSValue: &mockkms.CloseableKMS{}},
			WithVDRI(&mockvdri.MockVDRI{AcceptValue: true, StoreErr: fmt.Errorf("store error"),
				BuildFunc: func(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (doc *did.Doc, e error) {
					return &did.Doc{ID: "1:id:123"}, nil
				}}))
		doc, err := registry.Create("id")
		require.Error(t, err)
		require.Contains(t, err.Error(), "store error")
		require.Nil(t, doc)
	})
	t.Run("test success", func(t *testing.T) {
		registry := New(&mockprovider.Provider{KMSValue: &mockkms.CloseableKMS{}},
			WithVDRI(&mockvdri.MockVDRI{AcceptValue: true,
				BuildFunc: func(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (doc *did.Doc, e error) {
					return &did.Doc{ID: "1:id:123"}, nil
				}}))
		_, err := registry.Create("id")
		require.NoError(t, err)
	})
}
