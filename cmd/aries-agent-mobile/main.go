/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ariesagent

import (
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/command"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/rest"
)

// NewAriesAgent initializes and returns an implementation of the AriesController
func NewAriesAgent(local bool) (api.AriesController, error) {
	// TODO derive from some `options []Option` parameter instead of a boolean flag
	if !local {
		return rest.NewAries(), nil
	}

	// TODO unpack options here and pass them down
	return command.NewAries()
}
