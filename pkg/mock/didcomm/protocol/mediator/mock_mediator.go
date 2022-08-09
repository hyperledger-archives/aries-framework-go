/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
)

// MockMediatorSvc mock route service.
type MockMediatorSvc struct {
	service.Action
	service.Message
	ProtocolName       string
	HandleFunc         func(service.DIDCommMsg) (string, error)
	HandleOutboundFunc func(msg service.DIDCommMsg, myDID, theirDID string) (string, error)
	AcceptFunc         func(string) bool
	RegisterFunc       func(connectionID string, options ...mediator.ClientOption) error
	RouterEndpoint     string
	RoutingKeys        []string
	ConfigErr          error
	AddKeyErr          error
	UnregisterErr      error
	Connections        []string
	GetConnectionsErr  error
	AddKeyFunc         func(string) error
}

// Initialize service.
func (m *MockMediatorSvc) Initialize(interface{}) error {
	return nil
}

// HandleInbound msg.
func (m *MockMediatorSvc) HandleInbound(msg service.DIDCommMsg, ctx service.DIDCommContext) (string, error) {
	if m.HandleFunc != nil {
		return m.HandleFunc(msg)
	}

	return uuid.New().String(), nil
}

// HandleOutbound msg.
func (m *MockMediatorSvc) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	if m.HandleOutboundFunc != nil {
		return m.HandleOutboundFunc(msg, myDID, theirDID)
	}

	return "", nil
}

// Accept msg checks the msg type.
func (m *MockMediatorSvc) Accept(msgType string) bool {
	if m.AcceptFunc != nil {
		return m.AcceptFunc(msgType)
	}

	return true
}

// Name return service name.
func (m *MockMediatorSvc) Name() string {
	if m.ProtocolName != "" {
		return m.ProtocolName
	}

	return "route"
}

// Register registers agent with the router.
func (m *MockMediatorSvc) Register(connectionID string, options ...mediator.ClientOption) error {
	if m.RegisterFunc != nil {
		return m.RegisterFunc(connectionID, options...)
	}

	return nil
}

// Unregister unregisters the router.
func (m *MockMediatorSvc) Unregister(connID string) error {
	return m.UnregisterErr
}

// AddKey adds agents recKey to the router.
func (m *MockMediatorSvc) AddKey(connID, recKey string) error {
	if m.AddKeyErr != nil {
		return m.AddKeyErr
	}

	if m.AddKeyFunc != nil {
		return m.AddKeyFunc(recKey)
	}

	return nil
}

// Config gives back the router configuration.
func (m *MockMediatorSvc) Config(connID string) (*mediator.Config, error) {
	if m.ConfigErr != nil {
		return nil, m.ConfigErr
	}

	// default, route not registered error
	if m.RouterEndpoint == "" || m.RoutingKeys == nil {
		return nil, mediator.ErrRouterNotRegistered
	}

	return mediator.NewConfig(m.RouterEndpoint, m.RoutingKeys), nil
}

// GetConnections returns router`s connections.
func (m *MockMediatorSvc) GetConnections(...mediator.ConnectionOption) ([]string, error) {
	if m.GetConnectionsErr != nil {
		return nil, m.GetConnectionsErr
	}

	return m.Connections, nil
}
