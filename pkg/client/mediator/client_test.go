/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
)

// Ensure Client can emit events.
var _ service.Event = (*Client)(nil)

func TestNew(t *testing.T) {
	t.Run("test new client", func(t *testing.T) {
		svc, err := New(&mockprovider.Provider{
			ServiceValue: &mockroute.MockMediatorSvc{},
		},
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

	t.Run("test timeout is applied to options", func(t *testing.T) {
		timeout := 1 * time.Second

		option := WithTimeout(timeout)
		opts := &mediator.ClientOptions{}
		option(opts)

		require.Equal(t, timeout, opts.Timeout)
	})
}

func TestRegister(t *testing.T) {
	t.Run("test register - success", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ServiceValue: &mockroute.MockMediatorSvc{RegisterFunc: func(connectionID string, options ...mediator.ClientOption) error { // nolint: lll
				return nil
			}},
		})
		require.NoError(t, err)

		err = c.Register("conn")
		require.NoError(t, err)
	})

	t.Run("test register - error", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ServiceValue: &mockroute.MockMediatorSvc{RegisterFunc: func(connectionID string, options ...mediator.ClientOption) error { // nolint: lll
				return errors.New("register error")
			}},
		})
		require.NoError(t, err)

		err = c.Register("conn")
		require.Error(t, err)
		require.Contains(t, err.Error(), "router registration")
	})
}

func TestUnregister(t *testing.T) {
	t.Run("test unregister - success", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ServiceValue: &mockroute.MockMediatorSvc{},
		})
		require.NoError(t, err)

		err = c.Unregister("conn")
		require.NoError(t, err)
	})

	t.Run("test unregister - error", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ServiceValue: &mockroute.MockMediatorSvc{
				UnregisterErr: errors.New("unregister error"),
			},
		})
		require.NoError(t, err)

		err = c.Unregister("conn")
		require.Error(t, err)
		require.Contains(t, err.Error(), "router unregister")
	})
}

func TestGetConnection(t *testing.T) {
	t.Run("test get connection - success", func(t *testing.T) {
		routerConnectionID := "conn-abc"

		c, err := New(&mockprovider.Provider{
			ServiceValue: &mockroute.MockMediatorSvc{
				Connections: []string{routerConnectionID},
			},
		})
		require.NoError(t, err)

		conns, err := c.GetConnections()
		require.Equal(t, 1, len(conns))
		require.NoError(t, err)
		require.Equal(t, routerConnectionID, conns[0])
	})

	t.Run("test get connection - error", func(t *testing.T) {
		c, err := New(&mockprovider.Provider{
			ServiceValue: &mockroute.MockMediatorSvc{
				GetConnectionsErr: errors.New("get connections error"),
			},
		})
		require.NoError(t, err)

		conns, err := c.GetConnections()
		require.Error(t, err)
		require.Contains(t, err.Error(), "get router connections")
		require.Empty(t, conns)
	})
}

func TestClient_GetConfig(t *testing.T) {
	t.Run("returns configuration", func(t *testing.T) {
		endpoint := "http://example.com"
		keys := []string{"key1", "key2"}
		c, err := New(&mockprovider.Provider{
			ServiceValue: &mockroute.MockMediatorSvc{
				RouterEndpoint: endpoint,
				RoutingKeys:    keys,
			},
		})
		require.NoError(t, err)
		result, err := c.GetConfig("conn")
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, endpoint, result.Endpoint())
		require.Equal(t, keys, result.Keys())
	})
	t.Run("wraps config error", func(t *testing.T) {
		expected := errors.New("test")
		c, err := New(&mockprovider.Provider{
			ServiceValue: &mockroute.MockMediatorSvc{
				ConfigErr: expected,
			},
		})
		require.NoError(t, err)
		_, err = c.GetConfig("conn")
		require.Error(t, err)
		require.True(t, errors.Is(err, expected))
	})
}
