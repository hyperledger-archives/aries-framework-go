/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
)

func TestService_Name(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		prov, err := New(&protocol.MockProvider{})
		require.NoError(t, err)
		require.Equal(t, IssueCredential, prov.Name())
	})
}

func TestServiceNew(t *testing.T) {
	t.Run("test error from open store", func(t *testing.T) {
		_, err := New(
			&protocol.MockProvider{StoreProvider: &mockstorage.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("failed to open store")}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open store")
	})
}

func TestService_Handle(t *testing.T) {
	store := mockstorage.NewMockStoreProvider()

	s, err := New(
		&protocol.MockProvider{StoreProvider: store})
	require.NoError(t, err)

	//Request is sent by Bob
	request := &Request{
		Type:    RequestMsgType,
		ID:      randomString(),
		Comment: "alice sending request",
		//todo
	}

	// Alice receives an request credential from Bob
	payloadBytes, err := json.Marshal(request)
	require.NoError(t, err)

	msg, err := service.NewDIDCommMsg(payloadBytes)
	require.NoError(t, err)

	err = s.HandleInbound(msg)
	require.NoError(t, err)

	//Issue-credential is sent by Alice
	issue := &Request{
		Type:    IssueMsgType,
		ID:      randomString(),
		Comment: "alice sending request",
		//todo
	}

	// Alice receives an issue-credential from Bob
	payloadBytes, err = json.Marshal(issue)
	require.NoError(t, err)

	msg, err = service.NewDIDCommMsg(payloadBytes)
	require.NoError(t, err)

	err = s.HandleInbound(msg)
	require.NoError(t, err)

}
func TestStateFromMsgType(t *testing.T) {
	t.Run("requested", func(t *testing.T) {
		actual, err := stateFromMsgType(RequestMsgType)
		require.NoError(t, err)
		require.Equal(t, stateNameRequest, actual)
	})
	t.Run("issued", func(t *testing.T) {
		actual, err := stateFromMsgType(IssueMsgType)
		require.NoError(t, err)
		require.Equal(t, stateNameIssued, actual)
	})
}
func randomString() string {
	u := uuid.New()
	return u.String()
}
