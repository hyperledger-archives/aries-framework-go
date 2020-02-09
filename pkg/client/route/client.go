/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/route"
)

// provider contains dependencies for the route protocol and is typically created by using aries.Context()
type provider interface {
	Service(id string) (interface{}, error)
}

// Client enable access to route api.
type Client struct {
	routeSvc protocolService
}

// protocolService defines DID Exchange service.
type protocolService interface {
	// DIDComm service
	service.Handler

	// Register registers the agent with the router
	Register(connectionID string) error

	// Unregister unregisters the agent with the router
	Unregister() error
}

// New return new instance of route client.
func New(ctx provider) (*Client, error) {
	svc, err := ctx.Service(route.Coordination)
	if err != nil {
		return nil, err
	}

	routeSvc, ok := svc.(protocolService)
	if !ok {
		return nil, errors.New("cast service to route service failed")
	}

	return &Client{
		routeSvc: routeSvc,
	}, nil
}

// Register the agent with the router(passed in connectionID). This function asks router's
// permission to publish it's endpoint and routing keys.
func (c *Client) Register(connectionID string) error {
	if err := c.routeSvc.Register(connectionID); err != nil {
		return fmt.Errorf("router registration : %w", err)
	}

	return nil
}

// Unregister unregisters the agent with the router.
func (c *Client) Unregister() error {
	if err := c.routeSvc.Unregister(); err != nil {
		return fmt.Errorf("router unregister : %w", err)
	}

	return nil
}
