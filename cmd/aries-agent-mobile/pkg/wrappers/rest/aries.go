/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rest

import (
	"fmt"

	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/api"
	"github.com/hyperledger/aries-framework-go/cmd/aries-agent-mobile/pkg/wrappers"
)

// AriesREST is an Aries implementation with endpoints to execute operations
type AriesREST struct {
	endpoints map[string]map[string]*Endpoint
}

// NewAries returns a new AriesREST instance.
// Use this if you want your requests to be handled by a remote agent.
func NewAries() *AriesREST {
	endpoints := getProtocolEndpoints()

	return &AriesREST{endpoints}
}

// GetIntroduceController returns an IntroduceREST instance
func (ar *AriesREST) GetIntroduceController() (api.IntroduceController, error) {
	endpoints, ok := ar.endpoints[wrappers.ProtocolIntroduce]
	if !ok {
		return nil, fmt.Errorf("no endpoints found for protocol [%s]", wrappers.ProtocolIntroduce)
	}

	return &IntroduceREST{endpoints: endpoints}, nil
}
