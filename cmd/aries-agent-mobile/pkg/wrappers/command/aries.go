/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package command

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers"
	"github.com/hyperledger/aries-framework-go/pkg/controller"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"
)

// Aries is an implementation of AriesController which handles requests locally.
type Aries struct {
	framework *aries.Aries
	handlers  map[string]map[string]command.Exec
}

// NewAries returns a new Aries instance that contains handlers and an Aries framework instance.
func NewAries() (*Aries, error) {
	// TODO receive options
	storageProvider := mem.NewProvider()

	framework, err := aries.New(aries.WithStoreProvider(storageProvider))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Aries framework: %w", err)
	}

	context, err := framework.Context()
	if err != nil {
		return nil, fmt.Errorf("failed to get Framework context: %w", err)
	}

	commandHandlers, err := controller.GetCommandHandlers(context)
	if err != nil {
		return nil, fmt.Errorf("failed to get command handlers: %w", err)
	}

	handlers := make(map[string]map[string]command.Exec)
	populateHandlers(commandHandlers, handlers)

	return &Aries{framework, handlers}, nil
}

// GetIntroduceController returns an Introduce instance
func (a *Aries) GetIntroduceController() (api.IntroduceController, error) {
	handlers, ok := a.handlers[wrappers.ProtocolIntroduce]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for protocol [%s]", wrappers.ProtocolIntroduce)
	}

	return &Introduce{handlers: handlers}, nil
}

func populateHandlers(commands []command.Handler, pkgMap map[string]map[string]command.Exec) {
	for _, cmd := range commands {
		fnMap, ok := pkgMap[cmd.Name()]
		if !ok {
			fnMap = make(map[string]command.Exec)
		}

		fnMap[cmd.Method()] = cmd.Handle()
		pkgMap[cmd.Name()] = fnMap
	}
}
