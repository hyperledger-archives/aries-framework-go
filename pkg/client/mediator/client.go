/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

import (
	"errors"
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/didcomm/common/service"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
)

// provider contains dependencies for the route protocol and is typically created by using aries.Context()
type provider interface {
	Service(id string) (interface{}, error)
}

// Client enable access to route api.
type Client struct {
	service.Event
	routeSvc protocolService
}

// protocolService defines DID Exchange service.
type protocolService interface {
	// DIDComm service
	service.DIDComm

	// Register registers the agent with the router
	Register(connectionID string) error

	// Unregister unregisters the agent with the router
	Unregister() error

	// GetConnection returns the connectionID of the router.
	GetConnection() (string, error)

	// Config returns the router's configuration.
	Config() (*mediator.Config, error)

	// SetTimeout timeout value waiting for responses received from the router
	SetTimeout(timeout time.Duration)
}

const (
	updateTimeout = 5 * time.Second
)

// Option configures the route client and underlying service
type Option func(opts *mediatorOpts)

// mediatorOpts holds options for the router client
type mediatorOpts struct {
	timeout time.Duration
}

// WithTimeout option is for definition timeout value waiting for responses received from the router
func WithTimeout(t time.Duration) Option {
	return func(opts *mediatorOpts) {
		opts.timeout = t
	}
}

// New return new instance of route client.
func New(ctx provider, options ...Option) (*Client, error) {
	opts := &mediatorOpts{}

	defMediatorOpts(opts)

	// generate router config from options
	for _, option := range options {
		option(opts)
	}

	svc, err := ctx.Service(mediator.Coordination)
	if err != nil {
		return nil, err
	}

	routeSvc, ok := svc.(protocolService)
	if !ok {
		return nil, errors.New("cast service to route service failed")
	}

	routeSvc.SetTimeout(opts.timeout)

	return &Client{
		Event:    routeSvc,
		routeSvc: routeSvc,
	}, nil
}

// defMediatorOpts provides default router options
func defMediatorOpts(opts *mediatorOpts) {
	opts.timeout = updateTimeout
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

// GetConnection returns the connectionID of the router.
func (c *Client) GetConnection() (string, error) {
	connectionID, err := c.routeSvc.GetConnection()

	if err != nil {
		return "", fmt.Errorf("get router connectionID : %w", err)
	}

	return connectionID, nil
}

// GetConfig returns the router's configuration.
func (c *Client) GetConfig() (*mediator.Config, error) {
	conf, err := c.routeSvc.Config()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch routing configuration : %w", err)
	}

	return conf, nil
}
