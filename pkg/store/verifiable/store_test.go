/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable_test

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	. "github.com/hyperledger/aries-framework-go/pkg/store/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/store/verifiable/internal"
)

const (
	sampleCredentialName   = "sampleVCName"
	sampleCredentialID     = "sampleVCID"
	samplePresentationName = "sampleVPName"
	samplePresentationID   = "sampleVPID"
)

//nolint:gochecknoglobals
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

//nolint:gochecknoglobals
var udCredentialWithoutID = `

{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
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

  "expirationDate": "2020-01-01T19:23:24Z"
}
`

//nolint:lll
const udVerifiablePresentation = `{
        "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
        "type": ["VerifiablePresentation"],
		"holder": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "verifiableCredential": [{
            "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
            "credentialSchema": [],
            "credentialStatus": {
                "id": "http://issuer.vc.rest.example.com:8070/status/1",
                "type": "CredentialStatusList2017"
            },
            "credentialSubject": {
                "degree": {"degree": "MIT", "type": "BachelorDegree"},
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "name": "Jayden Doe",
                "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
            },
            "id": "https://example.com/credentials/9315d0fd-da93-436e-9e20-2121f2821df3",
            "issuanceDate": "2020-03-16T22:37:26.544Z",
            "issuer": {
                "id": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg",
                "name": "alice_ca31684e-6cbb-40f9-b7e6-87e1ab5661ae"
            },
            "proof": {
                "created": "2020-04-08T21:19:02Z",
                "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..yGHHYmRp4mWd918SDSzmBDs8eq-SX7WPl8moGB8oJeSqEMmuEiI81D4s5-BPWGmKy3VlCsKJxYrTNqrEGJpNAQ",
                "proofPurpose": "assertionMethod",
                "type": "Ed25519Signature2018",
                "verificationMethod": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg#xqc3gS1gz1vch7R3RvNebWMjLvBOY-n_14feCYRPsUo"
            },
            "type": ["VerifiableCredential", "UniversityDegreeCredential"]
        }],
        "proof": {
            "created": "2020-04-08T17:19:05-04:00",
            "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..0CH8GwphcMoQ0JHCm1O8n9ctM-s8hTfTuOa-WeQFSmPipaO41pECe7pQ4zDM6sp08W59pkrTz_U1PrwLlUyoBw",
            "proofPurpose": "assertionMethod",
            "type": "Ed25519Signature2018",
            "verificationMethod": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg#xqc3gS1gz1vch7R3RvNebWMjLvBOY-n_14feCYRPsUo"
        }
    }
`

//nolint:lll
const udPresentation = `{
        "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
        "type": ["VerifiablePresentation"],
		"holder": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "verifiableCredential": [{
            "@context": ["https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"],
            "credentialSchema": [],
            "credentialStatus": {
                "id": "http://issuer.vc.rest.example.com:8070/status/1",
                "type": "CredentialStatusList2017"
            },
            "credentialSubject": {
                "degree": {"degree": "MIT", "type": "BachelorDegree"},
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "name": "Jayden Doe",
                "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
            },
            "id": "https://example.com/credentials/9315d0fd-da93-436e-9e20-2121f2821df3",
            "issuanceDate": "2020-03-16T22:37:26.544Z",
            "issuer": {
                "id": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg",
                "name": "alice_ca31684e-6cbb-40f9-b7e6-87e1ab5661ae"
            },
            "proof": {
                "created": "2020-04-08T21:19:02Z",
                "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..yGHHYmRp4mWd918SDSzmBDs8eq-SX7WPl8moGB8oJeSqEMmuEiI81D4s5-BPWGmKy3VlCsKJxYrTNqrEGJpNAQ",
                "proofPurpose": "assertionMethod",
                "type": "Ed25519Signature2018",
                "verificationMethod": "did:elem:EiBJJPdo-ONF0jxqt8mZYEj9Z7FbdC87m2xvN0_HAbcoEg#xqc3gS1gz1vch7R3RvNebWMjLvBOY-n_14feCYRPsUo"
            },
            "type": ["VerifiableCredential", "UniversityDegreeCredential"]
        }]
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
				ErrOpenStoreHandle: fmt.Errorf("failed to open store"),
			},
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
				Store:  make(map[string]mockstore.DBEntry),
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
				Store:  make(map[string]mockstore.DBEntry),
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
				Store:  make(map[string]mockstore.DBEntry),
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

	t.Run("test save vc - with options", func(t *testing.T) {
		const (
			MyDID    = "MyDID"
			TheirDID = "TheirDID"
		)
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, s.SaveCredential(sampleCredentialName, &verifiable.Credential{ID: "vc1"},
			WithMyDID(MyDID), WithTheirDID(TheirDID)))

		records, err := s.GetCredentials()
		require.NoError(t, err)
		require.Equal(t, 1, len(records))

		require.Equal(t, MyDID, records[0].MyDID)
		require.Equal(t, TheirDID, records[0].TheirDID)
	})
}

func TestGetVC(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	t.Run("test success", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NoError(t, err)
		udVC, err := verifiable.ParseCredential([]byte(udCredential),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)
		require.NoError(t, s.SaveCredential(sampleCredentialName, udVC))
		vc, err := s.GetCredential("http://example.edu/credentials/1872")
		require.NoError(t, err)
		require.Equal(t, vc.ID, "http://example.edu/credentials/1872")

		records, err := s.GetCredentials()
		require.NoError(t, err)
		require.NotEmpty(t, records)

		for _, r := range records {
			require.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", r.SubjectID)
			require.Equal(t, "http://example.edu/credentials/1872", r.ID)
			require.Equal(t, "sampleVCName", r.Name)
		}
	})

	t.Run("test success - vc without ID", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NoError(t, err)
		udVC, err := verifiable.ParseCredential([]byte(udCredentialWithoutID),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)
		require.NoError(t, s.SaveCredential(sampleCredentialName, udVC))

		id, err := s.GetCredentialIDByName(sampleCredentialName)
		require.NoError(t, err)
		require.NotEmpty(t, id)

		vc, err := s.GetCredential(id)
		require.NoError(t, err)
		require.NotEmpty(t, vc)
	})

	t.Run("test error from store get", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrGet: fmt.Errorf("error get"),
			}),
			DocumentLoaderValue: loader,
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
			DocumentLoaderValue:  loader,
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
		rbytes, err := json.Marshal(&Record{
			ID:        sampleCredentialID,
			Name:      "",
			Context:   nil,
			Type:      nil,
			SubjectID: "",
		},
		)
		require.NoError(t, err)

		store := make(map[string]mockstore.DBEntry)
		store[internal.CredentialNameDataKey(sampleCredentialName)] = mockstore.DBEntry{Value: rbytes}

		s, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: store}},
		})
		require.NoError(t, err)

		id, err := s.GetCredentialIDByName(sampleCredentialName)
		require.NoError(t, err)
		require.Equal(t, sampleCredentialID, id)

		id, err = s.GetCredentialIDByName("some-random-id")
		require.Error(t, err)
		require.Empty(t, id)
		require.Contains(t, err.Error(), "fetch credential id based on name : data not found")
	})

	t.Run("test get credential based on name - db error", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
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

func TestGetCredentials(t *testing.T) {
	t.Run("test get credentials", func(t *testing.T) {
		store := make(map[string]mockstore.DBEntry)
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: store}},
		})
		require.NoError(t, err)

		records, err := s.GetCredentials()
		require.NoError(t, err)
		require.Equal(t, 0, len(records))

		err = s.SaveCredential(sampleCredentialName, &verifiable.Credential{ID: sampleCredentialID})
		require.NoError(t, err)

		records, err = s.GetCredentials()
		require.NoError(t, err)
		require.Equal(t, 1, len(records))
		require.Equal(t, records[0].Name, sampleCredentialName)
		require.Equal(t, records[0].ID, sampleCredentialID)

		// add some other values and make sure the GetCredential returns records as before
		store["dummy-value"] = mockstore.DBEntry{Value: []byte("dummy-key")}

		records, err = s.GetCredentials()
		require.NoError(t, err)
		require.Equal(t, 1, len(records))

		n := 10
		for i := 0; i < n; i++ {
			err = s.SaveCredential(sampleCredentialName+strconv.Itoa(i),
				&verifiable.Credential{ID: sampleCredentialID + strconv.Itoa(i)})
			require.NoError(t, err)
		}

		records, err = s.GetCredentials()
		require.Equal(t, 1+n, len(records))
		require.NoError(t, err)
	})
}

func TestSaveVP(t *testing.T) {
	t.Run("test save vp - success", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, s.SavePresentation(samplePresentationName, &verifiable.Presentation{ID: "vp1"}))
	})

	t.Run("test save vp - error from store put", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrPut: fmt.Errorf("error put"),
			}),
		})
		require.NoError(t, err)
		err = s.SavePresentation(samplePresentationName, &verifiable.Presentation{ID: "vp1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error put")
	})

	t.Run("test save vp - empty name", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrPut: fmt.Errorf("error put"),
			}),
		})
		require.NoError(t, err)
		err = s.SavePresentation("", &verifiable.Presentation{ID: "vp1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "presentation name is mandatory")
	})

	t.Run("test save vp - error getting existing mapping for name", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrGet: fmt.Errorf("error get"),
			}),
		})
		require.NoError(t, err)
		err = s.SavePresentation(samplePresentationName, &verifiable.Presentation{ID: "vp1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "get presentation id using name")
	})

	t.Run("test save vp - name already exists", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, s.SavePresentation(samplePresentationName, &verifiable.Presentation{ID: "vp1"}))

		err = s.SavePresentation(samplePresentationName, &verifiable.Presentation{ID: "vp2"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "presentation name already exists")
	})

	t.Run("test save vp - with options", func(t *testing.T) {
		const (
			MyDID    = "MyDID"
			TheirDID = "TheirDID"
		)
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, s.SavePresentation(samplePresentationName, &verifiable.Presentation{ID: "vp1"},
			WithMyDID(MyDID), WithTheirDID(TheirDID)))

		records, err := s.GetPresentations()
		require.NoError(t, err)
		require.Equal(t, 1, len(records))

		require.Equal(t, MyDID, records[0].MyDID)
		require.Equal(t, TheirDID, records[0].TheirDID)
	})
}

func TestGetVP(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	t.Run("test success - save presentation", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NoError(t, err)
		udVP, err := verifiable.ParsePresentation([]byte(udPresentation),
			verifiable.WithPresDisabledProofCheck(),
			verifiable.WithPresJSONLDDocumentLoader(loader))
		require.NoError(t, err)
		require.NoError(t, s.SavePresentation(samplePresentationName, udVP))

		id, err := s.GetPresentationIDByName(samplePresentationName)
		require.NoError(t, err)
		require.NotEmpty(t, id)

		vp, err := s.GetPresentation(id)
		require.NoError(t, err)
		require.Equal(t, vp.Type[0], "VerifiablePresentation")
		require.NotEmpty(t, vp.Credentials())
		require.EqualValues(t, vp.Credentials()[0].(map[string]interface{})["id"],
			"https://example.com/credentials/9315d0fd-da93-436e-9e20-2121f2821df3")
	})

	t.Run("test success - save VP", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NoError(t, err)
		udVP, err := verifiable.ParsePresentation([]byte(udVerifiablePresentation),
			verifiable.WithPresDisabledProofCheck(),
			verifiable.WithPresJSONLDDocumentLoader(loader))
		require.NoError(t, err)
		require.NoError(t, s.SavePresentation(samplePresentationName, udVP))

		id, err := s.GetPresentationIDByName(samplePresentationName)
		require.NoError(t, err)
		require.NotEmpty(t, id)

		vp, err := s.GetPresentation(id)
		require.NoError(t, err)
		require.Equal(t, vp.Type[0], "VerifiablePresentation")
		require.NotEmpty(t, vp.Credentials())
		require.EqualValues(t, vp.Credentials()[0].(map[string]interface{})["id"],
			"https://example.com/credentials/9315d0fd-da93-436e-9e20-2121f2821df3")
	})

	t.Run("test error from store get", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrGet: fmt.Errorf("error get"),
			}),
			DocumentLoaderValue: loader,
		})
		require.NoError(t, err)
		vp, err := s.GetPresentation("vpxyz")
		require.Error(t, err)
		require.Contains(t, err.Error(), "error get")
		require.Nil(t, vp)
	})

	t.Run("test error from new presentation", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NoError(t, err)
		require.NoError(t, s.SavePresentation(samplePresentationName, &verifiable.Presentation{ID: "vp1"}))
		require.NoError(t, err)

		vc, err := s.GetPresentation("vp1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "verifiable presentation is not valid")
		require.Nil(t, vc)
	})
}

func TestGetPresentationIDBasedOnName(t *testing.T) {
	t.Run("test get presentation based on name - success", func(t *testing.T) {
		rbytes, err := json.Marshal(&Record{
			ID:        samplePresentationID,
			Name:      "",
			Context:   nil,
			Type:      nil,
			SubjectID: "",
		},
		)
		require.NoError(t, err)

		store := make(map[string]mockstore.DBEntry)
		store[internal.PresentationNameDataKey(samplePresentationName)] = mockstore.DBEntry{Value: rbytes}

		s, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: store}},
		})
		require.NoError(t, err)

		id, err := s.GetPresentationIDByName(samplePresentationName)
		require.NoError(t, err)
		require.Equal(t, samplePresentationID, id)
	})

	t.Run("test get presentation based on name - db error", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrGet: fmt.Errorf("error get"),
			}),
		})
		require.NoError(t, err)

		id, err := s.GetPresentationIDByName(samplePresentationName)
		require.Error(t, err)
		require.Contains(t, err.Error(), "fetch presentation id based on name")
		require.Equal(t, "", id)
	})
}

func TestGetPresentations(t *testing.T) {
	t.Run("test get save & presentations", func(t *testing.T) {
		store := make(map[string]mockstore.DBEntry)
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: store}},
		})
		require.NoError(t, err)

		records, err := s.GetPresentations()
		require.NoError(t, err)
		require.Equal(t, 0, len(records))

		err = s.SavePresentation(samplePresentationName, &verifiable.Presentation{ID: samplePresentationID})
		require.NoError(t, err)

		records, err = s.GetPresentations()
		require.NoError(t, err)
		require.Equal(t, 1, len(records))
		require.Equal(t, records[0].Name, samplePresentationName)
		require.Equal(t, records[0].ID, samplePresentationID)

		// add some other values and make sure the GetCredential returns records as before
		store["dummy-value"] = mockstore.DBEntry{Value: []byte("dummy-key")}

		records, err = s.GetPresentations()
		require.NoError(t, err)
		require.Equal(t, 1, len(records))

		n := 10
		for i := 0; i < n; i++ {
			err = s.SavePresentation(samplePresentationName+strconv.Itoa(i),
				&verifiable.Presentation{ID: samplePresentationID + strconv.Itoa(i)})
			require.NoError(t, err)
		}

		records, err = s.GetPresentations()
		require.NoError(t, err)
		require.Len(t, records, 1+n)
	})

	t.Run("test get presentations", func(t *testing.T) {
		loader, err := ldtestutil.DocumentLoader()
		require.NoError(t, err)

		store := make(map[string]mockstore.DBEntry)
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: store}},
			DocumentLoaderValue:  loader,
		})
		require.NoError(t, err)

		udVP, err := verifiable.ParsePresentation([]byte(udVerifiablePresentation),
			verifiable.WithPresDisabledProofCheck(),
			verifiable.WithPresJSONLDDocumentLoader(loader))
		require.NoError(t, err)
		require.NoError(t, s.SavePresentation(samplePresentationName, udVP))

		records, err := s.GetPresentations()
		require.NoError(t, err)
		require.Len(t, records, 1)

		require.Equal(t, records[0].Name, samplePresentationName)
		require.Equal(t, records[0].SubjectID, udVP.Holder)
	})
}

func TestRemoveVC(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	t.Run("test remove vc - success", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NoError(t, err)
		udVC, err := verifiable.ParseCredential([]byte(udCredential),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)
		require.NoError(t, s.SaveCredential(sampleCredentialName, udVC))

		id, err := s.GetCredentialIDByName(sampleCredentialName)
		require.NoError(t, err)
		require.NotEmpty(t, id)

		vc, err := s.GetCredential(id)
		require.NoError(t, err)
		require.Equal(t, vc.Types[0], "VerifiableCredential")
		require.EqualValues(t, vc.ID,
			"http://example.edu/credentials/1872")

		err = s.RemoveCredentialByName(sampleCredentialName)
		require.NoError(t, err)

		_, err = s.GetCredentialIDByName(sampleCredentialName)
		require.Error(t, err)

		_, err = s.GetCredential(id)
		require.Error(t, err)
	})
	t.Run("test remove vc - error from store delete", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:     make(map[string]mockstore.DBEntry),
				ErrDelete: fmt.Errorf("error delete"),
			}),
			DocumentLoaderValue: loader,
		})
		require.NoError(t, err)
		udVC, err := verifiable.ParseCredential([]byte(udCredential),
			verifiable.WithDisabledProofCheck(),
			verifiable.WithJSONLDDocumentLoader(loader))
		require.NoError(t, err)
		require.NoError(t, s.SaveCredential(sampleCredentialName, udVC))

		err = s.RemoveCredentialByName(sampleCredentialName)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to delete credential")
	})
	t.Run("test remove vc - empty name", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store: make(map[string]mockstore.DBEntry),
			}),
		})
		require.NoError(t, err)
		err = s.RemoveCredentialByName("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "credential name is mandatory")
	})
	t.Run("test remove vc - error removing non-existing credential", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store: make(map[string]mockstore.DBEntry),
			}),
		})
		require.NoError(t, err)
		err = s.RemoveCredentialByName(sampleCredentialName)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get credential id using name")
	})
	t.Run("test remove vc - error removing non-existing credential", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrGet: fmt.Errorf("error get"),
			}),
		})
		require.NoError(t, err)
		err = s.RemoveCredentialByName(sampleCredentialName)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get credential id using name")
	})
}

func TestRemoveVP(t *testing.T) {
	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	t.Run("test remove vp - success", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			DocumentLoaderValue:  loader,
		})
		require.NoError(t, err)
		udVP, err := verifiable.ParsePresentation([]byte(udPresentation),
			verifiable.WithPresDisabledProofCheck(),
			verifiable.WithPresJSONLDDocumentLoader(loader))
		require.NoError(t, err)
		require.NoError(t, s.SavePresentation(samplePresentationName, udVP))

		id, err := s.GetPresentationIDByName(samplePresentationName)
		require.NoError(t, err)
		require.NotEmpty(t, id)

		vp, err := s.GetPresentation(id)
		require.NoError(t, err)
		require.Equal(t, vp.Type[0], "VerifiablePresentation")
		require.NotEmpty(t, vp.Credentials())
		require.EqualValues(t, vp.Credentials()[0].(map[string]interface{})["id"],
			"https://example.com/credentials/9315d0fd-da93-436e-9e20-2121f2821df3")

		err = s.RemovePresentationByName(samplePresentationName)
		require.NoError(t, err)

		_, err = s.GetPresentationIDByName(samplePresentationName)
		require.Error(t, err)

		_, err = s.GetPresentation(id)
		require.Error(t, err)
	})

	t.Run("test remove vp - error from store delete", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:     make(map[string]mockstore.DBEntry),
				ErrDelete: fmt.Errorf("error delete"),
			}),
			DocumentLoaderValue: loader,
		})
		require.NoError(t, err)
		udVP, err := verifiable.ParsePresentation([]byte(udPresentation),
			verifiable.WithPresDisabledProofCheck(),
			verifiable.WithPresJSONLDDocumentLoader(loader))
		require.NoError(t, err)
		require.NoError(t, s.SavePresentation(samplePresentationName, udVP))

		err = s.RemovePresentationByName(samplePresentationName)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to delete presentation")
	})
	t.Run("test remove vp - empty name", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store: make(map[string]mockstore.DBEntry),
			}),
		})
		require.NoError(t, err)
		err = s.RemovePresentationByName("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "presentation name is mandatory")
	})
	t.Run("test remove vp - error removing non-existing presentation", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store: make(map[string]mockstore.DBEntry),
			}),
		})
		require.NoError(t, err)
		err = s.RemovePresentationByName(samplePresentationName)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get presentation id using name")
	})
	t.Run("test remove vp - error getting id", func(t *testing.T) {
		s, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewCustomMockStoreProvider(&mockstore.MockStore{
				Store:  make(map[string]mockstore.DBEntry),
				ErrGet: fmt.Errorf("error get"),
			}),
		})
		require.NoError(t, err)
		err = s.RemovePresentationByName(samplePresentationName)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get presentation id using name")
	})
}
