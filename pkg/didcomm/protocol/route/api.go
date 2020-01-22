/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package route

// ProtocolService service interface for router.
type ProtocolService interface {
	// AddKey adds agents recKey to the router
	AddKey(recKey string) error

	// Config gives back the router configuration
	Config() (*Config, error)
}
