/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	mockroute "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol/route"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
)

func TestNew(t *testing.T) {
	t.Run("test new command", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceValue: &mockroute.MockRouteSvc{},
			},
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handlers := cmd.GetHandlers()
		require.Equal(t, 2, len(handlers))
	})

	t.Run("test new command - client creation fail", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{},
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
				ServiceValue: &mockroute.MockRouteSvc{},
			},
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
				ServiceValue: &mockroute.MockRouteSvc{},
			},
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
				ServiceValue: &mockroute.MockRouteSvc{},
			},
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
				ServiceValue: &mockroute.MockRouteSvc{
					RegisterFunc: func(connectionID string) error {
						return errors.New("register error")
					},
				},
			},
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
				ServiceValue: &mockroute.MockRouteSvc{},
			},
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
				ServiceValue: &mockroute.MockRouteSvc{
					UnregisterErr: errors.New("unregister error"),
				},
			},
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Unregister(&b, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "router unregister")
	})
}
