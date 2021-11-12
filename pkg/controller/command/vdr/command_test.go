/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
)

const sampleDIDName = "sampleDIDName"

//nolint:lll
const doc = `{
  "@context": ["https://www.w3.org/ns/did/v1","https://w3id.org/did/v2"],
  "id": "did:peer:21tDAKCERh95uGgKbJNHYp",
  "verificationMethod": [
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

func TestCreateDID(t *testing.T) {
	t.Run("test create did - success", func(t *testing.T) {
		didDoc, err := did.ParseDocument([]byte(doc))
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			VDRegistryValue:      &mockvdr.MockVDRegistry{CreateValue: didDoc},
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		createDIDReq := CreateDIDRequest{
			Method: "peer",
			DID:    json.RawMessage(doc),
			Opts:   map[string]interface{}{"k1": "v1"},
		}
		reqBytes, err := json.Marshal(createDIDReq)
		require.NoError(t, err)

		var getRW bytes.Buffer
		cmdErr := cmd.CreateDID(&getRW, bytes.NewBuffer(reqBytes))
		require.NoError(t, cmdErr)

		response := Document{}
		err = json.NewDecoder(&getRW).Decode(&response)
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.DID)
	})

	t.Run("test create did - invalid did doc", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			VDRegistryValue:      &mockvdr.MockVDRegistry{},
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		createDIDReq := CreateDIDRequest{Method: "peer", DID: []byte("{}"), Opts: map[string]interface{}{"k1": "v1"}}
		reqBytes, err := json.Marshal(createDIDReq)
		require.NoError(t, err)

		var getRW bytes.Buffer
		err = cmd.CreateDID(&getRW, bytes.NewBuffer(reqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "parse did doc")
	})

	t.Run("test create did - invalid request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.CreateDID(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test create did - no did method in the request", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.CreateDID(&b, bytes.NewBufferString("{}"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "did method is mandatory")
	})

	t.Run("test create did - create error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			VDRegistryValue:      &mockvdr.MockVDRegistry{CreateErr: fmt.Errorf("failed to create")},
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		createDIDReq := CreateDIDRequest{Method: "peer", DID: json.RawMessage(doc)}
		reqBytes, err := json.Marshal(createDIDReq)
		require.NoError(t, err)

		var b bytes.Buffer
		err = cmd.CreateDID(&b, bytes.NewBuffer(reqBytes))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create")
	})
}

func TestResolveDID(t *testing.T) {
	t.Run("test resolve did - success", func(t *testing.T) {
		didDoc, err := did.ParseDocument([]byte(doc))
		require.NoError(t, err)

		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			VDRegistryValue:      &mockvdr.MockVDRegistry{ResolveValue: didDoc},
		})
		require.NotNil(t, cmd)
		require.NoError(t, err)

		jsoStr := fmt.Sprintf(`{"id":"%s"}`, "did:peer:21tDAKCERh95uGgKbJNHYp")

		var getRW bytes.Buffer
		cmdErr := cmd.ResolveDID(&getRW, bytes.NewBufferString(jsoStr))
		require.NoError(t, cmdErr)

		response, err := did.ParseDocumentResolution(getRW.Bytes())
		require.NoError(t, err)

		// verify response
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.DIDDocument)
		require.NotEmpty(t, response.DIDDocument.ID)
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

		var b bytes.Buffer
		err = cmd.ResolveDID(&b, bytes.NewBufferString("{}"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "did is mandatory")
	})

	t.Run("test get did - resolve error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			VDRegistryValue:      &mockvdr.MockVDRegistry{ResolveErr: fmt.Errorf("failed to resolve")},
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
		s := make(map[string]mockstore.DBEntry)
		s["did:peer:21tDAKCERh95uGgKbJNHYp"] = mockstore.DBEntry{Value: []byte(doc)}

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

		var b bytes.Buffer
		err = cmd.GetDID(&b, bytes.NewBufferString("{}"))
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
			StorageProviderValue: mem.NewProvider(),
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
