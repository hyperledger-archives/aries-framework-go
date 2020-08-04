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

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	messagepickupSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/messagepickup"
	mockroute "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/messagepickup"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
)

const sampleConnRequest = `{"connectionID":"123-abc"}`
const sampleBatchPickupRequest = `{"connectionID":"123-abc", "batch_size": 100}`
const sampleEmptyConnectionRequest = `{"connectionID":""}`

func TestNew(t *testing.T) {
	t.Run("test new command", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination:          &mockroute.MockMediatorSvc{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		handlers := cmd.GetHandlers()
		require.Equal(t, 6, len(handlers))
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

func TestCommand_Register(t *testing.T) {
	t.Run("test register - success", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination:          &mockroute.MockMediatorSvc{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Register(&b, bytes.NewBufferString(sampleConnRequest))
		require.NoError(t, err)
	})

	t.Run("test register - empty connectionID", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination:          &mockroute.MockMediatorSvc{},
				},
			},
			false,
		)
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
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination:          &mockroute.MockMediatorSvc{},
				},
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
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination: &mockroute.MockMediatorSvc{
						UnregisterErr: errors.New("unregister error"),
					},
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

func TestCommand_Connection(t *testing.T) {
	t.Run("test get connection - success", func(t *testing.T) {
		routerConnectionID := "conn-abc"

		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination: &mockroute.MockMediatorSvc{
						ConnectionID: routerConnectionID,
					},
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
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination: &mockroute.MockMediatorSvc{
						GetConnectionIDErr: errors.New("get connectionID error"),
					},
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

func TestCommand_Reconnect(t *testing.T) {
	t.Run("test reconnect - success", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination:          &mockroute.MockMediatorSvc{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Reconnect(&b, bytes.NewBufferString(sampleConnRequest))
		require.NoError(t, err)
	})

	t.Run("test reconnect - empty connectionID", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination:          &mockroute.MockMediatorSvc{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Reconnect(&b, bytes.NewBufferString(sampleEmptyConnectionRequest))
		require.Error(t, err)
		require.Contains(t, err.Error(), "connectionID is mandatory")
	})

	t.Run("test reconnect - invalid request", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination:          &mockroute.MockMediatorSvc{},
				},
			},
			false,
		)
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
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination:          &mockroute.MockMediatorSvc{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.Status(&b, bytes.NewBufferString(sampleEmptyConnectionRequest))
		require.Error(t, err)
		require.Contains(t, err.Error(), "connectionID is mandatory")
	})

	t.Run("test status - invalid request", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination:          &mockroute.MockMediatorSvc{},
				},
			},
			false,
		)
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
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination:          &mockroute.MockMediatorSvc{},
				},
			},
			false,
		)
		require.NoError(t, err)
		require.NotNil(t, cmd)

		var b bytes.Buffer
		err = cmd.BatchPickup(&b, bytes.NewBufferString(sampleEmptyConnectionRequest))
		require.Error(t, err)
		require.Contains(t, err.Error(), "connectionID is mandatory")
	})

	t.Run("test batch pickup - invalid request", func(t *testing.T) {
		cmd, err := New(
			&mockprovider.Provider{
				ServiceMap: map[string]interface{}{
					messagepickupSvc.MessagePickup: &messagepickup.MockMessagePickupSvc{},
					mediator.Coordination:          &mockroute.MockMediatorSvc{},
				},
			},
			false,
		)
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
