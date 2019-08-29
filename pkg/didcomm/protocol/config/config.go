/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"github.com/hyperledger/aries-framework-go/pkg/config/lookup"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
)

//FromBackend returns config implementation for given backend
func FromBackend(configBackend api.ConfigBackend) api.ProtocolConfig {
	return &config{backend: lookup.New(configBackend)}
}

// config represents the aries configuration
type config struct {
	backend *lookup.ConfigLookup
}

// AgentLabel get agent label
func (c *config) AgentLabel() string {
	return c.backend.GetString("aries.agent.label")
}

// AgentServiceEndpoint get agent service endpoint
func (c *config) AgentServiceEndpoint() string {
	return c.backend.GetString("aries.agent.serviceEndpoint")
}
