/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ariesagent

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/command"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/config"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/logger"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers/rest"
	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

// New initializes and returns an implementation of the AriesController.
func New(opts *config.Options) (api.AriesController, error) {
	if opts.Logger != nil {
		log.Initialize(logger.New(opts.Logger))
	}

	if err := setLogLevel(opts.LogLevel); err != nil {
		return nil, err
	}

	if !opts.UseLocalAgent {
		return rest.NewAries(opts)
	}

	return command.NewAries(opts)
}

func setLogLevel(logLevel string) error {
	if logLevel == "" {
		return nil
	}

	level, err := log.ParseLevel(logLevel)
	if err != nil {
		return fmt.Errorf("failed to parse log level '%s' : %w", logLevel, err)
	}

	log.SetLevel("", level)

	return nil
}
