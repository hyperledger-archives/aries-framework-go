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

// New initializes and returns an implementation of the AriesController
func New(opts *config.Options) (api.AriesController, error) {
	if !opts.UseLocalAgent {
		return rest.NewAries(opts)
	}

	return command.NewAries(opts)
}
