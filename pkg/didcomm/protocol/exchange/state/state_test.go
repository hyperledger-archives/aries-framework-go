/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package state

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/storage/leveldb"
	"github.com/stretchr/testify/require"
)

func TestState(t *testing.T) {

	msg := map[string]interface{}{
		"@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/invitation",
		"@id":   "12345678900987654321",
		"label": "Alice",
		"did":   "did:sov:QmWbsNYhMrjHiqZDTUTEJs",
	}

	invitationBytes, err := json.Marshal(msg)
	require.NoError(t, err)
	path, cleanup := setupLevelDB(t)
	defer cleanup()

	prov, err := leveldb.NewProvider(path)
	require.NoError(t, err)
	dbstore, err := prov.GetStoreHandle()
	require.NoError(t, err)
	state := newState()
	handler := New(dbstore, state)

	current := handler.CheckState()
	require.Equal(t, current, "null")

	err = handler.Handle(invitationBytes)
	require.NoError(t, err)

	current = handler.CheckState()
	require.Equal(t, current, "invited")

	requestMsg := map[string]interface{}{
		"@id":   "12345678900987654321",
		"@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/request",
		"label": "Bob",
		"connection": map[string]interface{}{
			"did": "B.did@B:A",
			"did_doc": map[string]interface{}{
				"@context": "https://w3id.org/did/v1",
				// DID Doc contents here.
			},
		},
	}
	requestBytes, err := json.Marshal(requestMsg)
	require.NoError(t, err)

	err = handler.Handle(requestBytes)
	require.NoError(t, err)

	current = handler.CheckState()
	require.Equal(t, current, "requested")

	respMsg := map[string]interface{}{
		"@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/response",
		"@id":   "12345678900987654321",
		"~thread": map[string]interface{}{
			"thid": "12345678900987654321",
		},
		"connection~sig": map[string]interface{}{
			"@type":     "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/signature/1.0/ed25519Sha512_single",
			"signature": "<digital signature function output>",
			"sig_data":  "<base64URL(64bit_integer_from_unix_epoch||connection_attribute)>",
			"signers":   "<signing_verkey>",
		},
	}

	respBytes, err := json.Marshal(respMsg)
	require.NoError(t, err)
	err = handler.Handle(respBytes)
	require.NoError(t, err)

	current = handler.CheckState()
	require.Equal(t, current, "responded")

	ackMsg := map[string]interface{}{
		"@type":  "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0/ack",
		"@id":    "12345678900987654321",
		"status": "OK",
		"~thread": map[string]interface{}{
			"thid": "12345678900987654321",
		},
	}

	ackBytes, err := json.Marshal(ackMsg)
	require.NoError(t, err)
	err = handler.Handle(ackBytes)
	require.NoError(t, err)

	current = handler.CheckState()
	require.Equal(t, current, "completed")

}

func setupLevelDB(t testing.TB) (string, func()) {
	dbPath, err := ioutil.TempDir("", "db")
	if err != nil {
		t.Fatalf("Failed to create leveldb directory: %s", err)
	}
	return dbPath, func() {
		err := os.RemoveAll(dbPath)
		if err != nil {
			t.Fatalf("Failed to clear leveldb directory: %s", err)
		}
	}
}
