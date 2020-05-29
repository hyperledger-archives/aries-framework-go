/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
)

func TestNew(t *testing.T) {
	t.Run("test new command", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceValue: &mockroute.MockMediatorSvc{},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handlers := cmd.GetHandlers()
		require.Equal(t, 3, len(handlers))
	})

	t.Run("test new command - client creation fail", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{},
			false,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create route client")
		require.Nil(t, cmd)
	})
}

func TestRegisterRoute(t *testing.T) {
	t.Run("test register - success", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceValue: &mockroute.MockMediatorSvc{},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		jsonReq := `{"connectionID":"123-abc"}`
		var b bytes.Buffer
		err = cmd.Register(&b, bytes.NewBufferString(jsonReq))
		require.NoError(t, err)
	})

	t.Run("test register - empty connectionID", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceValue: &mockroute.MockMediatorSvc{},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		jsonReq := `{"connectionID":""}`
		var b bytes.Buffer
		err = cmd.Register(&b, bytes.NewBufferString(jsonReq))
		require.Error(t, err)
		require.Contains(t, err.Error(), "connectionID is mandatory")
	})

	t.Run("test register - empty connectionID", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceValue: &mockroute.MockMediatorSvc{},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Register(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test register - empty connectionID", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceValue: &mockroute.MockMediatorSvc{
					RegisterFunc: func(connectionID string) error {
						return errors.New("register error")
					},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		jsonReq := `{"connectionID":"123-abc"}`
		var b bytes.Buffer
		err = cmd.Register(&b, bytes.NewBufferString(jsonReq))
		require.Error(t, err)
		require.Contains(t, err.Error(), "router registration")
	})
}

func TestUnregisterRoute(t *testing.T) {
	t.Run("test unregister - success", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceValue: &mockroute.MockMediatorSvc{},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Unregister(&b, nil)
		require.NoError(t, err)
	})

	t.Run("test unregister - error", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceValue: &mockroute.MockMediatorSvc{
					UnregisterErr: errors.New("unregister error"),
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Unregister(&b, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "router unregister")
	})
}

func TestGetConnectionID(t *testing.T) {
	t.Run("test get connection - success", func(t *testing.T) {
		routerConnectionID := "conn-abc"

		cmd, err := New(
			&mockprovider.Provider{
				ServiceValue: &mockroute.MockMediatorSvc{
					ConnectionID: routerConnectionID,
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Connection(&b, nil)
		require.NoError(t, err)

		response := RegisterRoute{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.Equal(t, routerConnectionID, response.ConnectionID)
	})

	t.Run("test get connection - error", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceValue: &mockroute.MockMediatorSvc{
					GetConnectionIDErr: errors.New("get connectionID error"),
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Connection(&b, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get router connectionID")
	})
}
