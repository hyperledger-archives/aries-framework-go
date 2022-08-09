/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mediator

// ProtocolService service interface for router.
type ProtocolService interface {
	// AddKey adds agents recKey to the router
	AddKey(connID, recKey string) error

	// Config gives back the router configuration
	Config(connID string) (*Config, error)

	// GetConnections returns all router connections
	GetConnections(options ...ConnectionOption) ([]string, error)
}
