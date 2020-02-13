/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/route"
)

// MockRouteSvc mock route service
type MockRouteSvc struct {
	ProtocolName       string
	HandleFunc         func(service.DIDCommMsg) (string, error)
	HandleOutboundFunc func(msg service.DIDCommMsg, myDID, theirDID string) (string, error)
	AcceptFunc         func(string) bool
	RegisterFunc       func(connectionID string) error
	RouterEndpoint     string
	RoutingKeys        []string
	ConfigErr          error
	AddKeyErr          error
	UnregisterErr      error
}

// HandleInbound msg
func (m *MockRouteSvc) HandleInbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	if m.HandleFunc != nil {
		return m.HandleFunc(msg)
	}

	return uuid.New().String(), nil
}

// HandleOutbound msg
func (m *MockRouteSvc) HandleOutbound(msg service.DIDCommMsg, myDID, theirDID string) (string, error) {
	if m.HandleOutboundFunc != nil {
		return m.HandleOutboundFunc(msg, myDID, theirDID)
	}

	return "", nil
}

// Accept msg checks the msg type
func (m *MockRouteSvc) Accept(msgType string) bool {
	if m.AcceptFunc != nil {
		return m.AcceptFunc(msgType)
	}

	return true
}

// Name return service name
func (m *MockRouteSvc) Name() string {
	if m.ProtocolName != "" {
		return m.ProtocolName
	}

	return "route"
}

// Register registers agent with the router.
func (m *MockRouteSvc) Register(connectionID string) error {
	if m.RegisterFunc != nil {
		return m.RegisterFunc(connectionID)
	}

	return nil
}

// Unregister unregisters the router
func (m *MockRouteSvc) Unregister() error {
	return m.UnregisterErr
}

// AddKey adds agents recKey to the router
func (m *MockRouteSvc) AddKey(recKey string) error {
	return m.AddKeyErr
}

// Config gives back the router configuration
func (m *MockRouteSvc) Config() (*route.Config, error) {
	if m.ConfigErr != nil {
		return nil, m.ConfigErr
	}

	// default, route not registered error
	if m.RouterEndpoint == "" || m.RoutingKeys == nil {
		return nil, route.ErrRouterNotRegistered
	}

	return route.NewConfig(m.RouterEndpoint, m.RoutingKeys), nil
}
