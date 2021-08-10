/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ld

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ldcontext/remote"
	"github.com/hyperledger/aries-framework-go/pkg/ld"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
)

// provider contains dependencies for the JSON-LD service.
type provider interface {
	JSONLDContextStore() ldstore.ContextStore
	JSONLDRemoteProviderStore() ldstore.RemoteProviderStore
}

// Client is a JSON-LD SDK client.
type Client struct {
	service ld.Service
}

// NewClient returns a new instance of Client.
func NewClient(ctx provider, opts ...Option) *Client {
	c := &Client{
		service: ld.New(ctx),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// AddContexts adds JSON-LD contexts to the underlying storage.
func (c *Client) AddContexts(documents []ldcontext.Document) error {
	return c.service.AddContexts(documents)
}

// AddRemoteProvider adds remote provider and JSON-LD contexts from that provider.
func (c *Client) AddRemoteProvider(providerEndpoint string, opts ...remote.ProviderOpt) (string, error) {
	return c.service.AddRemoteProvider(providerEndpoint, opts...)
}

// RefreshRemoteProvider updates contexts from the remote provider.
func (c *Client) RefreshRemoteProvider(providerID string, opts ...remote.ProviderOpt) error {
	return c.service.RefreshRemoteProvider(providerID, opts...)
}

// DeleteRemoteProvider deletes remote provider and contexts from that provider.
func (c *Client) DeleteRemoteProvider(providerID string, opts ...remote.ProviderOpt) error {
	return c.service.DeleteRemoteProvider(providerID, opts...)
}

// GetAllRemoteProviders gets all remote providers.
func (c *Client) GetAllRemoteProviders() ([]ldstore.RemoteProviderRecord, error) {
	return c.service.GetAllRemoteProviders()
}

// RefreshAllRemoteProviders updates contexts from all remote providers.
func (c *Client) RefreshAllRemoteProviders(opts ...remote.ProviderOpt) error {
	return c.service.RefreshAllRemoteProviders(opts...)
}

// Option configures the JSON-LD client.
type Option func(c *Client)

// WithLDService sets the custom JSON-LD service.
func WithLDService(svc ld.Service) Option {
	return func(c *Client) {
		c.service = svc
	}
}
