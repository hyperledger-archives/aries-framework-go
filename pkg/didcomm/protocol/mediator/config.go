/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

// Config provides the router configuration.
type Config struct {
	routerEndpoint string
	routingKeys    []string
}

// NewConfig creates new config instance.
func NewConfig(endpoint string, keys []string) *Config {
	return &Config{
		routerEndpoint: endpoint,
		routingKeys:    keys,
	}
}

// Endpoint returns router endpoint.
func (c *Config) Endpoint() string {
	return c.routerEndpoint
}

// Keys returns routing keys.
func (c *Config) Keys() []string {
	return c.routingKeys
}
