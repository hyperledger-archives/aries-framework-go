/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	messagepickupSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/messagepickup"
	oobsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/messagepickup"
	mockoob "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/outofband"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

const (
	sampleConnRequest            = `{"connectionID":"123-abc"}`
	sampleBatchPickupRequest     = `{"connectionID":"123-abc", "batch_size": 100}`
	sampleEmptyConnectionRequest = `{"connectionID":""}`
	sampleErr                    = "sample-error"
)

func TestNew(t *testing.T) {
	t.Run("test new command", func(t *testing.T) {
		cmd, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handlers := cmd.GetHandlers()
		require.Equal(t, 7, len(handlers))
	})

	t.Run("test new command - client creation fail", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{}, false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "create route client")
		require.Nil(t, cmd)
	})

	t.Run("test new command - out of band client creation fail", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination:          &mockroute.MockMediatorSvc{},
				},
			},
			false,
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create out-of-band client")
		require.Nil(t, cmd)
	})
}

func TestCommand_Register(t *testing.T) {
	t.Run("test register - success", func(t *testing.T) {
		cmd, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Register(&b, bytes.NewBufferString(sampleConnRequest))
		require.NoError(t, err)
	})

	t.Run("test register - empty connectionID", func(t *testing.T) {
		cmd, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Register(&b, bytes.NewBufferString(sampleEmptyConnectionRequest))
		require.Error(t, err)
		require.Contains(t, err.Error(), "connectionID is mandatory")
	})

	t.Run("test register - empty connectionID", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination:          &mockroute.MockMediatorSvc{},
					oobsvc.Name:                    &mockoob.MockOobService{},
				},
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
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination: &mockroute.MockMediatorSvc{
						RegisterFunc: func(connectionID string, options ...mediator.ClientOption) error {
							return errors.New("register error")
						},
					},
					oobsvc.Name: &mockoob.MockOobService{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Register(&b, bytes.NewBufferString(sampleConnRequest))
		require.Error(t, err)
		require.Contains(t, err.Error(), "router registration")
	})
}

func TestCommand_Unregister(t *testing.T) {
	t.Run("test unregister - success", func(t *testing.T) {
		cmd, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Unregister(&b, bytes.NewBufferString(`{"connectionID":"xyz"}`))
		require.NoError(t, err)
	})

	t.Run("unregister - decode error", func(t *testing.T) {
		cmd, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Unregister(&b, bytes.NewBufferString(`}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("unregister - no connection id", func(t *testing.T) {
		cmd, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Unregister(&b, bytes.NewBufferString(`{}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "connectionID is mandatory")
	})

	t.Run("test unregister - error", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination: &mockroute.MockMediatorSvc{
						UnregisterErr: errors.New("unregister error"),
					},
					oobsvc.Name: &mockoob.MockOobService{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Unregister(&b, bytes.NewBufferString(`{"connectionID":"xyz"}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "router unregister")
	})
}

func TestCommand_Connections(t *testing.T) {
	t.Run("test get connection - success", func(t *testing.T) {
		routerConnectionID := "conn-abc"

		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination: &mockroute.MockMediatorSvc{
						Connections: []string{routerConnectionID},
					},
					oobsvc.Name: &mockoob.MockOobService{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		testcases := []struct {
			name  string
			input string
		}{
			{
				name:  "no filters",
				input: `{}`,
			},
			{
				name:  "didcomm v1 only",
				input: `{"didcomm_v1": true}`,
			},
			{
				name:  "didcomm v2 only",
				input: `{"didcomm_v2": true}`,
			},
		}

		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				var b bytes.Buffer
				err = cmd.Connections(&b, bytes.NewBufferString(tc.input))
				require.NoError(t, err)

				response := ConnectionsResponse{}
				err = json.NewDecoder(&b).Decode(&response)
				require.NoError(t, err)
				require.Equal(t, routerConnectionID, response.Connections[0])
			})
		}
	})

	t.Run("test get connection - read request error", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination:          &mockroute.MockMediatorSvc{},
					oobsvc.Name:                    &mockoob.MockOobService{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Connections(&b, &errReader{err: fmt.Errorf("expected error")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "read request")
	})

	t.Run("test get connection - decode request error", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination:          &mockroute.MockMediatorSvc{},
					oobsvc.Name:                    &mockoob.MockOobService{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Connections(&b, bytes.NewBufferString("{"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "decode request")
	})

	t.Run("test get connection - invalid filter options error", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination:          &mockroute.MockMediatorSvc{},
					oobsvc.Name:                    &mockoob.MockOobService{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Connections(&b, bytes.NewBufferString(`{"didcomm_v1": true, "didcomm_v2": true}`))
		require.Error(t, err)
		require.Contains(t, err.Error(), "at the same time")
	})

	t.Run("test get connection - error", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination: &mockroute.MockMediatorSvc{
						GetConnectionsErr: errors.New("get connections error"),
					},
					oobsvc.Name: &mockoob.MockOobService{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Connections(&b, bytes.NewBufferString("{}"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "get router connections")
	})
}

func TestCommand_Reconnect(t *testing.T) {
	t.Run("test reconnect - success", func(t *testing.T) {
		cmd, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Reconnect(&b, bytes.NewBufferString(sampleConnRequest))
		require.NoError(t, err)
	})

	t.Run("test reconnect - empty connectionID", func(t *testing.T) {
		cmd, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Reconnect(&b, bytes.NewBufferString(sampleEmptyConnectionRequest))
		require.Error(t, err)
		require.Contains(t, err.Error(), "connectionID is mandatory")
	})

	t.Run("test reconnect - invalid request", func(t *testing.T) {
		cmd, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Reconnect(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test register - failure", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{
						NoopErr: errors.New("reconnect error"),
					},
					mediator.Coordination: &mockroute.MockMediatorSvc{},
					oobsvc.Name:           &mockoob.MockOobService{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Reconnect(&b, bytes.NewBufferString(sampleConnRequest))
		require.Error(t, err)
		require.Contains(t, err.Error(), "reconnect error")
	})
}

func TestCommand_Status(t *testing.T) {
	t.Run("test status - success", func(t *testing.T) {
		const sampleID = "sample-status-id"
		const size = 64
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{
						StatusRequestFunc: func(connectionID string) (*messagepickupSvc.Status, error) {
							return &messagepickupSvc.Status{ID: sampleID, TotalSize: size}, nil
						},
					},
					mediator.Coordination: &mockroute.MockMediatorSvc{},
					oobsvc.Name:           &mockoob.MockOobService{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Status(&b, bytes.NewBufferString(sampleConnRequest))
		require.NoError(t, err)

		response := StatusResponse{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.Equal(t, size, response.TotalSize)
		require.Equal(t, sampleID, response.ID)
	})

	t.Run("test status - empty connectionID", func(t *testing.T) {
		cmd, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Status(&b, bytes.NewBufferString(sampleEmptyConnectionRequest))
		require.Error(t, err)
		require.Contains(t, err.Error(), "connectionID is mandatory")
	})

	t.Run("test status - invalid request", func(t *testing.T) {
		cmd, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Status(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test status - failure", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{
						StatusRequestErr: errors.New("status error"),
					},
					mediator.Coordination: &mockroute.MockMediatorSvc{},
					oobsvc.Name:           &mockoob.MockOobService{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Status(&b, bytes.NewBufferString(sampleConnRequest))
		require.Error(t, err)
		require.Contains(t, err.Error(), "status error")
	})
}

func TestCommand_BatchPickup(t *testing.T) {
	t.Run("test batch pickup - success", func(t *testing.T) {
		const count = 64
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{
						BatchPickupFunc: func(connectionID string, size int) (int, error) {
							return count, nil
						},
					},
					mediator.Coordination: &mockroute.MockMediatorSvc{},
					oobsvc.Name:           &mockoob.MockOobService{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.BatchPickup(&b, bytes.NewBufferString(sampleBatchPickupRequest))
		require.NoError(t, err)

		response := BatchPickupResponse{}
		err = json.NewDecoder(&b).Decode(&response)
		require.NoError(t, err)
		require.Equal(t, count, response.MessageCount)
	})

	t.Run("test batch pickup - empty connectionID", func(t *testing.T) {
		cmd, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.BatchPickup(&b, bytes.NewBufferString(sampleEmptyConnectionRequest))
		require.Error(t, err)
		require.Contains(t, err.Error(), "connectionID is mandatory")
	})

	t.Run("test batch pickup - invalid request", func(t *testing.T) {
		cmd, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.BatchPickup(&b, bytes.NewBufferString("--"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	t.Run("test batch pickup - failure", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{
						BatchPickupErr: errors.New("batch pickup error"),
					},
					mediator.Coordination: &mockroute.MockMediatorSvc{},
					oobsvc.Name:           &mockoob.MockOobService{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.BatchPickup(&b, bytes.NewBufferString(sampleConnRequest))
		require.Error(t, err)
		require.Contains(t, err.Error(), "batch pickup error")
	})
}

func TestCommand_ReconnectAll(t *testing.T) {
	t.Run("test with empty connections", func(t *testing.T) {
		c, err := New(newMockProvider(nil), false)
		require.NoError(t, err)
		require.NotNil(t, c)

		var b bytes.Buffer
		cmdErr := c.ReconnectAll(&b, bytes.NewBufferString(""))
		require.NoError(t, cmdErr)
	})

	t.Run("test failure while getting connections", func(t *testing.T) {
		prov := newMockProvider(map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{
				GetConnectionsErr: fmt.Errorf(sampleErr),
			},
			oobsvc.Name:                    &mockoob.MockOobService{},
			messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
		})

		c, err := New(prov, false)
		require.NoError(t, err)
		require.NotNil(t, c)

		var b bytes.Buffer
		cmdErr := c.ReconnectAll(&b, bytes.NewBufferString(""))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), sampleErr)
	})

	t.Run("test success with active connections", func(t *testing.T) {
		prov := newMockProvider(map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{
				Connections: []string{"sample-connection"},
			},
			oobsvc.Name:                    &mockoob.MockOobService{},
			messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
		})

		c, err := New(prov, false)
		require.NoError(t, err)
		require.NotNil(t, c)

		var b bytes.Buffer
		cmdErr := c.ReconnectAll(&b, bytes.NewBufferString(""))
		require.NoError(t, cmdErr)
	})

	t.Run("test failure due to mediator command errors", func(t *testing.T) {
		prov := newMockProvider(map[string]interface{}{
			mediator.Coordination: &mockroute.MockMediatorSvc{
				Connections: []string{"sample-connection"},
			},
			oobsvc.Name: &mockoob.MockOobService{},
			messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{
				NoopErr: fmt.Errorf(sampleErr),
			},
		})

		c, err := New(prov, false)
		require.NoError(t, err)
		require.NotNil(t, c)

		var b bytes.Buffer
		cmdErr := c.ReconnectAll(&b, bytes.NewBufferString(""))
		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), sampleErr)
	})
}

func newMockProvider(serviceMap map[string]interface{}) *mockprovider.Provider {
	if serviceMap == nil {
		serviceMap = map[string]interface{}{
			mediator.Coordination:          &mockroute.MockMediatorSvc{},
			oobsvc.Name:                    &mockoob.MockOobService{},
			messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
		}
	}

	return &mockprovider.Provider{
		ServiceMap:                        serviceMap,
		StorageProviderValue:              mockstorage.NewMockStoreProvider(),
		ProtocolStateStorageProviderValue: mockstorage.NewMockStoreProvider(),
	}
}

type errReader struct {
	err error
}

func (e *errReader) Read([]byte) (int, error) {
	return 0, e.err
}
