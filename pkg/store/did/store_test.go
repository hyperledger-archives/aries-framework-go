/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/common/model"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	didstore "github.com/hyperledger/aries-framework-go/pkg/store/did"
)

const (
	sampleDIDName = "sampleDIDName"
	sampleDIDID   = "sampleDIDID"
)

func TestNew(t *testing.T) {
	t.Run("test new store", func(t *testing.T) {
		s, err := didstore.New(&mockprovider.Provider{
			StorageProviderValue: mem.NewProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("test error from open store", func(t *testing.T) {
		s, err := didstore.New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("failed to open store"),
			},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
		require.Nil(t, s)
	})
}

func TestSaveDID(t *testing.T) {
	t.Run("test save did doc - success", func(t *testing.T) {
		s, err := didstore.New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, s.SaveDID(sampleDIDName, &did.Doc{ID: "did1"}))
	})

	t.Run("test save did doc - error from store put", func(t *testing.T) {
		s, err := didstore.New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrPut: fmt.Errorf("error put"),
			}),
		})
		require.NoError(t, err)
		err = s.SaveDID(sampleDIDName, &did.Doc{ID: "did1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})

	t.Run("test save did doc - empty name", func(t *testing.T) {
		s, err := didstore.New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrPut: fmt.Errorf("error put"),
			}),
		})
		require.NoError(t, err)
		err = s.SaveDID("", &did.Doc{ID: "did1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "did name is mandatory")
	})

	t.Run("test save did doc - error getting existing mapping for name", func(t *testing.T) {
		s, err := didstore.New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrGet: fmt.Errorf("error get"),
			}),
		})
		require.NoError(t, err)
		err = s.SaveDID(sampleDIDName, &did.Doc{ID: "did1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "get did using name")
	})

	t.Run("test save did doc - name already exists", func(t *testing.T) {
		s, err := didstore.New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, s.SaveDID(sampleDIDName, &did.Doc{ID: "did1"}))

		err = s.SaveDID(sampleDIDName, &did.Doc{ID: "did2"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "did name already exists")
	})
}

func TestGetDIDDoc(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		s, err := didstore.New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		didDoc := createDIDDoc()
		require.NoError(t, s.SaveDID(sampleDIDName, didDoc))
		doc, err := s.GetDID((didDoc.ID))
		require.NoError(t, err)
		require.Equal(t, doc.ID, didDoc.ID)
	})

	t.Run("test error from store get", func(t *testing.T) {
		s, err := didstore.New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrGet: fmt.Errorf("error get"),
			}),
		})
		require.NoError(t, err)
		didDoc, err := s.GetDID("did1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error get")
		require.Nil(t, didDoc)
	})

	t.Run("test error data not found", func(t *testing.T) {
		s, err := didstore.New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, s.SaveDID(sampleDIDName, &did.Doc{ID: "did1"}))
		require.NoError(t, err)
		didDoc, err := s.GetDID("did12")
		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")
		require.Nil(t, didDoc)
	})
}

func TestDIDBasedOnName(t *testing.T) {
	t.Run("test get didDoc based on name - success", func(t *testing.T) {
		store := make(map[string]mockstore.DBEntry)
		store[didNameDataKey(sampleDIDName)] = mockstore.DBEntry{Value: []byte(sampleDIDID)}

		s, err := didstore.New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: store}},
		})
		require.NoError(t, err)

		id, err := s.GetDIDByName(sampleDIDName)
		require.NoError(t, err)
		require.Equal(t, sampleDIDID, id)
	})

	t.Run("test get didDoc based on name - db error", func(t *testing.T) {
		s, err := didstore.New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrGet: fmt.Errorf("error get"),
			}),
		})
		require.NoError(t, err)

		id, err := s.GetDIDByName(sampleDIDName)
		require.Error(t, err)
		require.Contains(t, err.Error(), "fetch did doc id based on name")
		require.Equal(t, "", id)
	})
}

func TestGetCredentials(t *testing.T) {
	t.Run("test get dids", func(t *testing.T) {
		store := make(map[string]mockstore.DBEntry)
		s, err := didstore.New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: store}},
		})
		require.NoError(t, err)

		records := s.GetDIDRecords()
		require.Equal(t, 0, len(records))

		err = s.SaveDID(sampleDIDName, &did.Doc{ID: sampleDIDID})
		require.NoError(t, err)

		records = s.GetDIDRecords()
		require.Equal(t, 1, len(records))
		require.Equal(t, records[0].Name, sampleDIDName)
		require.Equal(t, records[0].ID, sampleDIDID)

		// add some other values and make sure the GetCredential returns records as before
		store["dummy-value"] = mockstore.DBEntry{Value: []byte("dummy-key")}

		records = s.GetDIDRecords()
		require.Equal(t, 1, len(records))

		n := 10
		for i := 0; i < n; i++ {
			err = s.SaveDID(sampleDIDName+strconv.Itoa(i),
				&did.Doc{ID: sampleDIDID + strconv.Itoa(i)})
			require.NoError(t, err)
		}

		records = s.GetDIDRecords()
		require.Equal(t, 1+n, len(records))
	})
}

func didNameDataKey(name string) string {
	return fmt.Sprintf("didname_%s", name)
}

func createDIDDoc() *did.Doc {
	pubKey, _ := generateKeyPair()
	return createDIDDocWithKey(pubKey)
}

func generateKeyPair() (string, []byte) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	return base58.Encode(pubKey[:]), privKey
}

func createDIDDocWithKey(pub string) *did.Doc {
	const (
		didFormat    = "did:%s:%s"
		didPKID      = "%s#keys-%d"
		didServiceID = "%s#endpoint-%d"
		method       = "test"
	)

	id := fmt.Sprintf(didFormat, method, pub[:16])
	pubKeyID := fmt.Sprintf(didPKID, id, 1)
	pubKey := did.VerificationMethod{
		ID:         pubKeyID,
		Type:       "Ed25519VerificationKey2018",
		Controller: id,
		Value:      []byte(pub),
	}
	services := []did.Service{
		{
			ID:              fmt.Sprintf(didServiceID, id, 1),
			Type:            "did-communication",
			ServiceEndpoint: model.NewDIDCommV1Endpoint("http://localhost:58416"),
			Priority:        0,
			RecipientKeys:   []string{pubKeyID},
		},
	}
	createdTime := time.Now()
	didDoc := &did.Doc{
		Context:            []string{did.ContextV1},
		ID:                 id,
		VerificationMethod: []did.VerificationMethod{pubKey},
		Service:            services,
		Created:            &createdTime,
		Updated:            &createdTime,
	}

	return didDoc
}
