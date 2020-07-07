/*
Copyright Scoir Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package messagepickup

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	mockpickup "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/messagepickup"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
)

func TestNew(t *testing.T) {
	t.Run("test new client", func(t *testing.T) {
		client, err := New(&mockprovider.Provider{
			ServiceValue: &mockpickup.MockMessagePickupSvc{},
		})
		require.NoError(t, err)
		require.NotNil(t, client)
	})

	t.Run("test error from get service from context", func(t *testing.T) {
		_, err := New(&mockprovider.Provider{ServiceErr: fmt.Errorf("service error")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "service error")
	})

	t.Run("test error from cast service", func(t *testing.T) {
		_, err := New(&mockprovider.Provider{ServiceValue: nil})
		require.Error(t, err)
		require.Contains(t, err.Error(), "cast service to message pickup service failed")
	})
}

func TestStatusRequest(t *testing.T) {
	t.Run("status request - success", func(t *testing.T) {
		client, err := New(&mockprovider.Provider{
			ServiceValue: &mockpickup.MockMessagePickupSvc{},
		})
		require.NoError(t, err)

		_, err = client.StatusRequest("connID")
		require.NoError(t, err)
	})

	t.Run("status request - status request error", func(t *testing.T) {
		client, err := New(&mockprovider.Provider{
			ServiceValue: &mockpickup.MockMessagePickupSvc{
				StatusRequestErr: errors.New("service error"),
			},
		})
		require.NoError(t, err)

		_, err = client.StatusRequest("connID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "service error")
	})
}

func TestBatchPickup(t *testing.T) {
	t.Run("batch pickup - success", func(t *testing.T) {
		client, err := New(&mockprovider.Provider{
			ServiceValue: &mockpickup.MockMessagePickupSvc{},
		})
		require.NoError(t, err)

		_, err = client.BatchPickup("connID", 1)
		require.NoError(t, err)
	})

	t.Run("batch pickup - batch pick up error", func(t *testing.T) {
		client, err := New(&mockprovider.Provider{
			ServiceValue: &mockpickup.MockMessagePickupSvc{
				BatchPickupErr: errors.New("service error"),
			},
		})
		require.NoError(t, err)

		_, err = client.BatchPickup("connID", 1)
		require.Error(t, err)
		require.Contains(t, err.Error(), "service error")
	})
}

func TestNoop(t *testing.T) {
	t.Run("noop - success", func(t *testing.T) {
		client, err := New(&mockprovider.Provider{
			ServiceValue: &mockpickup.MockMessagePickupSvc{},
		})
		require.NoError(t, err)

		err = client.Noop("connID")
		require.NoError(t, err)
	})

	t.Run("noop - service error", func(t *testing.T) {
		client, err := New(&mockprovider.Provider{
			ServiceValue: &mockpickup.MockMessagePickupSvc{
				NoopErr: errors.New("service error"),
			},
		})
		require.NoError(t, err)

		err = client.Noop("connID")
		require.Error(t, err)
		require.Contains(t, err.Error(), "service error")
	})
}
