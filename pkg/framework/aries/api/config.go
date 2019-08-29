/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

//ConfigProvider provides config backend for aries
type ConfigProvider func() (ConfigBackend, error)

//ConfigBackend backend for all config types in aries
type ConfigBackend interface {
	Lookup(key string) (interface{}, bool)
}

//ProtocolConfig contains configuration items for protocol.
type ProtocolConfig interface {
	AgentLabel() string
	AgentServiceEndpoint() string
}
