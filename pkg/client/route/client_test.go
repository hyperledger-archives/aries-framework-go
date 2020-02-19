/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	mockroute "github.com/hyperledger/aries-framework-go/pkg/internal/mock/didcomm/protocol/route"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/internal/mock/provider"
)

func TestNew(t *testing.T) {
	t.Run("test new client", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceValue: &mockroute.MockRouteSvc{}},
		)
		require.NoError(t, err)
		require.NotNil(t, svc)
	})

	t.Run("test error from get service from context", func(t *testing.T) {
		_, err := New(&mockprovider.Provider{ServiceErr: fmt.Errorf("service error")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "service error")
	})

	t.Run("test error from cast service", func(t *testing.T) {
		_, err := New(&mockprovider.Provider{ServiceValue: nil})
		require.Error(t, err)
		require.Contains(t, err.Error(), "cast service to route service failed")
	})
}

func TestRegister(t *testing.T) {
	t.Run("test register - success", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ServiceValue: &mockroute.MockRouteSvc{RegisterFunc: func(connectionID string) error {
				return nil
			}}})
		require.NoError(t, err)

		err = c.Register("conn1")
		require.NoError(t, err)
	})

	t.Run("test register - error", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ServiceValue: &mockroute.MockRouteSvc{RegisterFunc: func(connectionID string) error {
				return errors.New("register error")
			}}})
		require.NoError(t, err)

		err = c.Register("conn1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "router registration")
	})
}

func TestUnregister(t *testing.T) {
	t.Run("test unregister - success", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ServiceValue: &mockroute.MockRouteSvc{},
		})
		require.NoError(t, err)

		err = c.Unregister()
		require.NoError(t, err)
	})

	t.Run("test unregister - error", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ServiceValue: &mockroute.MockRouteSvc{
				UnregisterErr: errors.New("unregister error"),
			},
		})
		require.NoError(t, err)

		err = c.Unregister()
		require.Error(t, err)
		require.Contains(t, err.Error(), "router unregister")
	})
}

func TestGetConnection(t *testing.T) {
	t.Run("test get connection - success", func(t *testing.T) {
		routerConnectionID := "conn-abc"

		c, err := New(&mockprovider.Provider{
			ServiceValue: &mockroute.MockRouteSvc{
				ConnectionID: routerConnectionID,
			},
		})
		require.NoError(t, err)

		connID, err := c.GetConnection()
		require.NoError(t, err)
		require.Equal(t, routerConnectionID, connID)
	})

	t.Run("test get connection - error", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ServiceValue: &mockroute.MockRouteSvc{
				GetConnectionIDErr: errors.New("get connection id error"),
			},
		})
		require.NoError(t, err)

		connID, err := c.GetConnection()
		require.Error(t, err)
		require.Contains(t, err.Error(), "get router connectionID")
		require.Empty(t, connID)
	})
}
