/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdri

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
)

const sampleDIDName = "sampleDIDName"

//nolint:lll
const doc = `{
  "@context": ["https://w3id.org/did/v1","https://w3id.org/did/v2"],
  "id": "did:peer:21tDAKCERh95uGgKbJNHYp",
  "publicKey": [
    {
      "id": "did:peer:123456789abcdefghi#keys-1",
      "type": "Secp256k1VerificationKey2018",
      "controller": "did:peer:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    },
    {
      "id": "did:peer:123456789abcdefghw#key2",
      "type": "RsaVerificationKey2018",
      "controller": "did:peer:123456789abcdefghw",
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryQICCl6NZ5gDKrnSztO\n3Hy8PEUcuyvg/ikC+VcIo2SFFSf18a3IMYldIugqqqZCs4/4uVW3sbdLs/6PfgdX\n7O9D22ZiFWHPYA2k2N744MNiCD1UE+tJyllUhSblK48bn+v1oZHCM0nYQ2NqUkvS\nj+hwUU3RiWl7x3D2s9wSdNt7XUtW05a/FXehsPSiJfKvHJJnGOX0BgTvkLnkAOTd\nOrUZ/wK69Dzu4IvrN4vs9Nes8vbwPa/ddZEzGR0cQMt0JBkhk9kU/qwqUseP1QRJ\n5I1jR4g8aYPL/ke9K35PxZWuDp3U0UPAZ3PjFAh+5T+fc7gzCs9dPzSHloruU+gl\nFQIDAQAB\n-----END PUBLIC KEY-----"
    }
  ]
}`

func TestOperation_CreatePublicDID(t *testing.T) {
	t.Run("Test successful create public DID with method", func(t *testing.T) {
		cmd, err := New(&protocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handlers := cmd.GetHandlers()
		require.NotEmpty(t, handlers)

		var b bytes.Buffer
		req := []byte(`{"method":"sidetree"}`)
		cmdErr := cmd.CreatePublicDID(&b, bytes.NewBuffer(req))
		require.NoError(t, cmdErr)

		var response CreatePublicDIDResponse
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.DID)

		doc, err := did.ParseDocument(response.DID)
		require.NoError(t, err)
		require.NoError(t, err)

		require.NotEmpty(t, doc.ID)
		require.NotEmpty(t, doc.PublicKey)
		require.NotEmpty(t, doc.Service)
	})

	t.Run("Test successful create public DID with request header", func(t *testing.T) {
		cmd, err := New(&protocol.MockProvider{})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		req := []byte(`{"method":"sidetree", "header":"{}"}`)
		cmdErr := cmd.CreatePublicDID(&b, bytes.NewBuffer(req))
		require.NoError(t, cmdErr)

		var response CreatePublicDIDResponse
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.DID)

		doc, err := did.ParseDocument(response.DID)
		require.NoError(t, err)

		require.NotEmpty(t, doc.ID)
		require.NotEmpty(t, doc.PublicKey)
		require.NotEmpty(t, doc.Service)
	})

	t.Run("Test create public DID validation error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NoError(t, err)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		req := []byte(`"""`)
		cmdErr := cmd.CreatePublicDID(&b, bytes.NewBuffer(req))

		require.Error(t, cmdErr)
		require.Equal(t, cmdErr.Type(), command.ValidationError)
		require.Equal(t, cmdErr.Code(), InvalidRequestErrorCode)
		require.Contains(t, cmdErr.Error(), "cannot unmarshal")

		req = []byte(`{}`)
		cmdErr = cmd.CreatePublicDID(&b, bytes.NewBuffer(req))

		require.Error(t, cmdErr)
		require.Equal(t, cmdErr.Type(), command.ValidationError)
		require.Equal(t, cmdErr.Code(), InvalidRequestErrorCode)
		require.Contains(t, cmdErr.Error(), errDIDMethodMandatory)
	})

	t.Run("Failed Create public DID, VDRI error", func(t *testing.T) {
		const errMsg = "just fail it error"
		cmd, err := New(&protocol.MockProvider{CustomVDRI: &mockvdri.MockVDRIRegistry{CreateErr: fmt.Errorf(errMsg)}})
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		req := []byte(`{"method":"sidetree"}`)
		cmdErr := cmd.CreatePublicDID(&b, bytes.NewBuffer(req))
		require.Error(t, cmdErr)
		require.Equal(t, cmdErr.Type(), command.ExecuteError)
		require.Equal(t, cmdErr.Code(), CreatePublicDIDError)
		require.Contains(t, cmdErr.Error(), errMsg)
	})
}

func TestBuildSideTreeRequest(t *testing.T) {
	registry := mockvdri.MockVDRIRegistry{}
	didDoc, err := registry.Create("sidetree")
	require.NoError(t, err)
	require.NotNil(t, didDoc)

	b, err := didDoc.JSONBytes()
	require.NoError(t, err)

	r, err := getBasicRequestBuilder(`{"operation":"create"}`)(b)
	require.NoError(t, err)
	require.NotNil(t, r)

	r, err = getBasicRequestBuilder(`--`)(b)
	require.Error(t, err)
	require.Nil(t, r)
}

func TestNew(t *testing.T) {
	t.Run("test new command - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		handlers := cmd.GetHandlers()
		require.Equal(t, 5, len(handlers))
	})

	t.Run("test new command - did store error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("error opening the store"),
			},
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "new did store")
		require.Nil(t, cmd)
	})
}

func TestSaveDID(t *testing.T) {
	t.Run("test save did - success", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		didReq := DIDArgs{
			Document: Document{DID: json.RawMessage(doc)},
			Name:     sampleDIDName,
		}
		didReqBytes, err := json.Marshal(didReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SaveDID(&b, bytes.NewBuffer(didReqBytes))
		require.NoError(t, err)
	})
	t.Run("test save did - empty name", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		didReq := DIDArgs{
			Document: Document{DID: json.RawMessage(doc)},
		}
		didReqBytes, err := json.Marshal(didReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SaveDID(&b, bytes.NewBuffer(didReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "name is mandatory")
	})

	t.Run("test save did - invalid request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.SaveDID(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test save did - validation error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		didReq := DIDArgs{
			Document: Document{DID: json.RawMessage("")},
			Name:     sampleDIDName,
		}
		didReqBytes, err := json.Marshal(didReq)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.SaveDID(&b, bytes.NewBuffer(didReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse did doc")
	})

	t.Run("test save did - store error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				Store: &mockstore.MockStore{
					ErrPut: fmt.Errorf("put error"),
				},
			},
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		didReq := DIDArgs{
			Document: Document{DID: json.RawMessage(doc)},
			Name:     sampleDIDName,
		}

		didReqBytes, err := json.Marshal(didReq)
		require.NoError(t, err)

		var b bytes.Buffer

		err = cmd.SaveDID(&b, bytes.NewBuffer(didReqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "save did doc")
	})
}

func TestResolveDID(t *testing.T) {
	t.Run("test resolve did - success", func(t *testing.T) {
		didDoc, err := did.ParseDocument([]byte(doc))
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			VDRIRegistryValue:    &mockvdri.MockVDRIRegistry{ResolveValue: didDoc},
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"id":"%s"}`, "did:peer:21tDAKCERh95uGgKbJNHYp")

		var getRW bytes.Buffer
		cmdErr := cmd.ResolveDID(&getRW, bytes.NewBufferString(jsoStr))
		require.NoError(t, cmdErr)

		response := Document{}
		err = json.NewDecoder(&getRW).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.DID)
	})

	t.Run("test get did - invalid request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.ResolveDID(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test get did - no did in the request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{}`)

		var b bytes.Buffer
		err = cmd.ResolveDID(&b, bytes.NewBufferString(jsoStr))
		require.Error(t, err)
		require.Contains(t, err.Error(), "did is mandatory")
	})

	t.Run("test get did - resolve error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{StorageProviderValue: mockstore.NewMockStoreProvider(),
			VDRIRegistryValue: &mockvdri.MockVDRIRegistry{ResolveErr: fmt.Errorf("failed to resolve")},
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"id":"%s"}`, "did:peer:21tDAKCERh95uGgKbJNHYp")

		var b bytes.Buffer
		err = cmd.ResolveDID(&b, bytes.NewBufferString(jsoStr))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve")
	})
}

func TestGetDID(t *testing.T) {
	t.Run("test get did - success", func(t *testing.T) {
		s := make(map[string][]byte)
		s["did:peer:21tDAKCERh95uGgKbJNHYp"] = []byte(doc)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{Store: &mockstore.MockStore{Store: s}},
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"id":"%s"}`, "did:peer:21tDAKCERh95uGgKbJNHYp")

		var getRW bytes.Buffer
		cmdErr := cmd.GetDID(&getRW, bytes.NewBufferString(jsoStr))
		require.NoError(t, cmdErr)

		response := Document{}
		err = json.NewDecoder(&getRW).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.DID)
	})

	t.Run("test get did - invalid request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.GetDID(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test get did - no did in the request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{}`)

		var b bytes.Buffer
		err = cmd.GetDID(&b, bytes.NewBufferString(jsoStr))
		require.Error(t, err)
		require.Contains(t, err.Error(), "did is mandatory")
	})

	t.Run("test get did - store error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				Store: &mockstore.MockStore{
					ErrGet: fmt.Errorf("get error"),
				},
			},
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"id":"%s"}`, "did:peer:21tDAKCERh95uGgKbJNHYp")

		var b bytes.Buffer
		err = cmd.GetDID(&b, bytes.NewBufferString(jsoStr))
		require.Error(t, err)
		require.Contains(t, err.Error(), "get did")
	})
}

func TestGetDIDRecords(t *testing.T) {
	t.Run("test get did records", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		// save did with name
		didReq := DIDArgs{
			Document: Document{DID: json.RawMessage(doc)},
			Name:     sampleDIDName,
		}
		didReqBytes, err := json.Marshal(didReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.SaveDID(&b, bytes.NewBuffer(didReqBytes))
		require.NoError(t, err)

		var getRW bytes.Buffer
		cmdErr := cmd.GetDIDRecords(&getRW, nil)
		require.NoError(t, cmdErr)

		var response DIDRecordResult
		err = json.NewDecoder(&getRW).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.Equal(t, 1, len(response.Result))
	})
}
