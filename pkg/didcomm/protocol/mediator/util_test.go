/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetRouterConfig(t *testing.T) {
	t.Run("test get router config - ro router configured", func(t *testing.T) {
		endpoint, routingKeys, err := GetRouterConfig(&mockRouteSvc{}, "conn", ENDPOINT)
		require.NoError(t, err)
		require.Equal(t, ENDPOINT, endpoint)
		require.Equal(t, 0, len(routingKeys))
	})

	t.Run("test get router config - router configured", func(t *testing.T) {
		routeKeys := []string{"abc", "xyz"}
		endpoint, routingKeys, err := GetRouterConfig(
			&mockRouteSvc{
				RouterEndpoint: ENDPOINT,
				RoutingKeys:    routeKeys,
			},
			"conn",
			"http://override-url.com",
		)
		require.NoError(t, err)
		require.Equal(t, ENDPOINT, endpoint)
		require.Equal(t, routeKeys, routingKeys)
	})

	t.Run("test get router config - router error", func(t *testing.T) {
		endpoint, routingKeys, err := GetRouterConfig(
			&mockRouteSvc{
				ConfigErr: errors.New("router error"),
			},
			"conn",
			ENDPOINT,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "fetch router config")
		require.Empty(t, endpoint)
		require.Nil(t, routingKeys)
	})
}

func TestAddKeyToRouter(t *testing.T) {
	t.Run("test add key to router - success", func(t *testing.T) {
		err := AddKeyToRouter(&mockRouteSvc{}, "conn", ENDPOINT)
		require.NoError(t, err)
	})

	t.Run("test add key to router - router not registered", func(t *testing.T) {
		err := AddKeyToRouter(&mockRouteSvc{
			AddKeyErr: ErrRouterNotRegistered,
		}, "conn", ENDPOINT)
		require.NoError(t, err)
	})

	t.Run("test add key to router - router error", func(t *testing.T) {
		err := AddKeyToRouter(&mockRouteSvc{
			AddKeyErr: errors.New("router error"),
		}, "conn", ENDPOINT)
		require.EqualError(t, err, "addKey: router error")
	})
}

type mockRouteSvc struct {
	Connections    []string
	ConnectionsErr error
	RouterEndpoint string
	RoutingKeys    []string
	ConfigErr      error
	AddKeyErr      error
}

// AddKey adds agents recKey to the router.
func (m *mockRouteSvc) AddKey(connID, recKey string) error {
	return m.AddKeyErr
}

// AddKey adds agents recKey to the router.
func (m *mockRouteSvc) GetConnections(...ConnectionOption) ([]string, error) {
	return m.Connections, m.ConnectionsErr
}

// Config gives back the router configuration.
func (m *mockRouteSvc) Config(connID string) (*Config, error) {
	if m.ConfigErr != nil {
		return nil, m.ConfigErr
	}

	// default, route not registered error
	if m.RouterEndpoint == "" || m.RoutingKeys == nil {
		return nil, ErrRouterNotRegistered
	}

	return NewConfig(m.RouterEndpoint, m.RoutingKeys), nil
}
