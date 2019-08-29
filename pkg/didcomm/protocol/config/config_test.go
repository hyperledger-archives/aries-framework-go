/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"bytes"
	"testing"

	conf "github.com/hyperledger/aries-framework-go/pkg/config"
	"github.com/stretchr/testify/require"
)

var configYAML = `
aries:
  agent:
    label: agent
    serviceEndpoint: https://example.com/endpoint
`

func TestConfig_AgentLabel(t *testing.T) {
	buf := bytes.NewBuffer([]byte(configYAML))
	configBackend, err := conf.FromReader(buf, "yaml")()
	require.NoError(t, err)
	c := FromBackend(configBackend)
	require.Equal(t, "agent", c.AgentLabel())
}

func TestConfig_AgentServiceEndpoint(t *testing.T) {
	buf := bytes.NewBuffer([]byte(configYAML))
	configBackend, err := conf.FromReader(buf, "yaml")()
	require.NoError(t, err)
	c := FromBackend(configBackend)
	require.Equal(t, "https://example.com/endpoint", c.AgentServiceEndpoint())
}
