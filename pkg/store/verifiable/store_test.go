/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"

	"github.com/stretchr/testify/require"

	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

const sampleCredentialName = "sampleVCName"
const sampleCredentialID = "sampleVCID"

//nolint:gochecknoglobals,lll
var udCredential = `

{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "http://example.edu/credentials/1872",
  "type": [
    "VerifiableCredential",
    "UniversityDegreeCredential"
  ],
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree"
    },
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  },

  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
  },

  "issuanceDate": "2010-01-01T19:23:24Z",

  "expirationDate": "2020-01-01T19:23:24Z",

  "credentialStatus": {
    "id": "https://example.edu/status/24",
    "type": "CredentialStatusList2017"
  },

  "evidence": [{
    "id": "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d4231",
    "type": ["DocumentVerification"],
    "verifier": "https://example.edu/issuers/14",
    "evidenceDocument": "DriversLicense",
    "subjectPresence": "Physical",
    "documentPresence": "Physical"
  },{
    "id": "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192dxyzab",
    "type": ["SupportingActivity"],
    "verifier": "https://example.edu/issuers/14",
    "evidenceDocument": "Fluid Dynamics Focus",
    "subjectPresence": "Digital",
    "documentPresence": "Digital"
  }],

  "termsOfUse": [
    {
      "type": "IssuerPolicy",
      "id": "http://example.com/policies/credential/4",
      "profile": "http://example.com/profiles/credential",
      "prohibition": [
        {
          "assigner": "https://example.edu/issuers/14",
          "assignee": "AllVerifiers",
          "target": "http://example.edu/credentials/3732",
          "action": [
            "Archival"
          ]
        }
      ]
    }
  ],

  "refreshService": {
    "id": "https://example.edu/refresh/3732",
    "type": "ManualRefreshService2018"
  }
}
`

func TestNew(t *testing.T) {
	t.Run("test new store", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("test error from open store", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("failed to open store")},
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
		require.Nil(t, s)
	})
}

func TestSaveVC(t *testing.T) {
	t.Run("test save vc - success", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, s.SaveCredential(sampleCredentialName, &verifiable.Credential{ID: "vc1"}))
	})

	t.Run("test save vc - error from store put", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: fmt.Errorf("error put"),
			}),
		})
		require.NoError(t, err)
		err = s.SaveCredential(sampleCredentialName, &verifiable.Credential{ID: "vc1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})

	t.Run("test save vc - empty name", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrPut: fmt.Errorf("error put"),
			}),
		})
		require.NoError(t, err)
		err = s.SaveCredential("", &verifiable.Credential{ID: "vc1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential name is mandatory")
	})

	t.Run("test save vc - error getting existing mapping for name", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrGet: fmt.Errorf("error get"),
			}),
		})
		require.NoError(t, err)
		err = s.SaveCredential(sampleCredentialName, &verifiable.Credential{ID: "vc1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "get credential id using name")
	})

	t.Run("test save vc - name already exists", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, s.SaveCredential(sampleCredentialName, &verifiable.Credential{ID: "vc1"}))

		err = s.SaveCredential(sampleCredentialName, &verifiable.Credential{ID: "vc2"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential name already exists")
	})
}

func TestGetVC(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		udVC, _, err := verifiable.NewCredential([]byte(udCredential))
		require.NoError(t, err)
		require.NoError(t, s.SaveCredential(sampleCredentialName, udVC))
		vc, err := s.GetCredential("http://example.edu/credentials/1872")
		require.NoError(t, err)
		require.Equal(t, vc.ID, "http://example.edu/credentials/1872")
	})

	t.Run("test error from store get", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrGet: fmt.Errorf("error get"),
			}),
		})
		require.NoError(t, err)
		vc, err := s.GetCredential("vc1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error get")
		require.Nil(t, vc)
	})

	t.Run("test error from new credential", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, s.SaveCredential(sampleCredentialName, &verifiable.Credential{ID: "vc1"}))
		require.NoError(t, err)
		vc, err := s.GetCredential("vc1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential type of unknown structure")
		require.Nil(t, vc)
	})
}

func TestGetCredentialIDBasedOnName(t *testing.T) {
	t.Run("test get credential based on name - success", func(t *testing.T) {
		store := make(map[string][]byte)
		store[sampleCredentialName] = []byte(sampleCredentialID)

		s, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: store}},
		})
		require.NoError(t, err)

		id, err := s.GetCredentialIDByName(sampleCredentialName)
		require.NoError(t, err)
		require.Equal(t, sampleCredentialID, id)
	})

	t.Run("test get credential based on name - db error", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string][]byte),
				ErrGet: fmt.Errorf("error get"),
			}),
		})
		require.NoError(t, err)

		id, err := s.GetCredentialIDByName(sampleCredentialName)
		require.Error(t, err)
		require.Contains(t, err.Error(), "fetch credential id based on name")
		require.Equal(t, "", id)
	})
}
