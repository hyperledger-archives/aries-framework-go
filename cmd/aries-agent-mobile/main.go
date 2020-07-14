/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ariesagent

import (
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/command"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/config"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/rest"
)

// NewAriesAgent initializes and returns an implementation of the AriesController
func NewAriesAgent(opts *config.Options) (api.AriesController, error) {
	if !opts.UseLocalAgent {
		return rest.NewAries(opts), nil
	}

	return command.NewAries(opts)
}
